"""Log-adapter + transparent reverse proxy in front of the real,
unmodified, pinned-vulnerable httpd:2.4.49 backend (see ../httpd/).

This is the "sidecar/adapter that owns $EVENT_LOG, POST /reset, and
translates the component's native output into our JSON-lines schema" that
scoring/manifests/m5_vulnerable_component.yaml's original TODO called for.
It is deliberately NOT a Flask app like the other targets: this challenge's
exploit (CVE-2021-41773 / CVE-2021-42013) only works if the exact
percent-encoded request path reaches the real Apache byte-for-byte, and a
WSGI/Werkzeug app would percent-decode and normalize that path before this
code ever saw it, silently breaking the exploit even though the real
backend is genuinely vulnerable. http.server.BaseHTTPRequestHandler never
touches request-target encoding - self.path is exactly what was sent on
the wire - so it's used directly here instead.

Every fact this adapter logs is read off the REAL backend's real response
(status code, response body) - it never inspects or replays the request
itself as "proof"; the actual httpd:2.4.49 container is what's being
exploited, this just watches and reports.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import re
import socketserver
import time
from pathlib import Path

EVENT_LOG = Path(os.environ.get("EVENT_LOG", "/var/log/targets/vulnerable_component/events.log"))
FLAG = os.environ.get("FLAG", "FLAG{outdated_apache_cgi_rce_2026}")
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")
BACKEND_HOST = os.environ.get("BACKEND_HOST", "target_vulnerable_component_httpd")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "80"))
LISTEN_PORT = int(os.environ.get("PORT", "5000"))

# The well-known CVE-2021-41773/CVE-2021-42013 request shape: two or more
# repeated segments walking out of /cgi-bin/, either the double-encoded
# ".%%32%65/" form (the one that actually reaches RCE via mod_cgid) or the
# single-encoded "%2e%2e/" form (the plain file-read variant).
CVE_TRAVERSAL_RE = re.compile(
    r"^/cgi-bin/(?:(?:\.%%32%65/)|(?:%2e%2e/)){2,}",
    re.IGNORECASE,
)

HOP_BY_HOP = {"connection", "content-length", "transfer-encoding", "keep-alive", "host"}


def log_event(event: str, **fields) -> None:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "event": event, **fields}
    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self) -> None:
        # self.path is the raw request-target exactly as received - never
        # percent-decoded or normalized by http.server. That transparency
        # is load-bearing (see module docstring).
        raw_path = self.path
        bare_path = raw_path.split("?", 1)[0]

        if bare_path == "/reset":
            self._handle_reset()
            return
        if bare_path == "/healthz":
            self._respond(200, b'{"status": "ok"}', content_type="application/json")
            return

        content_length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(content_length) if content_length else b""

        try:
            status, headers, resp_body = self._forward(raw_path, body)
        except (OSError, TimeoutError) as exc:
            self._respond(502, f"backend unavailable: {exc}".encode())
            return

        self._log_from_response(bare_path, status, resp_body)
        self._respond(status, resp_body, extra_headers=headers)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = _handle

    def _forward(self, raw_path: str, body: bytes):
        conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=35)
        try:
            conn.putrequest(self.command, raw_path, skip_host=True, skip_accept_encoding=True)
            for key, value in self.headers.items():
                if key.lower() not in HOP_BY_HOP:
                    conn.putheader(key, value)
            conn.putheader("Host", BACKEND_HOST)
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(message_body=body if body else None)
            resp = conn.getresponse()
            resp_body = resp.read()
            headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP_BY_HOP]
            return resp.status, headers, resp_body
        finally:
            conn.close()

    def _handle_reset(self) -> None:
        if not RESET_TOKEN or self.headers.get("X-Reset-Token") != RESET_TOKEN:
            self._respond(403, b'{"error": "forbidden"}', content_type="application/json")
            return
        EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
        EVENT_LOG.write_text("")
        self._respond(200, b'{"status": "reset"}', content_type="application/json")

    def _respond(self, status: int, body: bytes, extra_headers=None, content_type: str | None = None) -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        for key, value in extra_headers or []:
            if content_type and key.lower() == "content-type":
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _log_from_response(self, path: str, status: int, body: bytes) -> None:
        log_event("page_view", path=path, status=status)

        if path == "/server-status" and status == 200:
            log_event("version_disclosed", status=status)

        if path.startswith("/cgi-bin/"):
            log_event("cgi_surface_probed", path=path, status=status)

        if CVE_TRAVERSAL_RE.match(path):
            log_event("cve_specific_probe", path=path, status=status)
            if status == 200:
                log_event("traversal_bypass_confirmed", path=path, status=status)
                # The real backend's real response body actually contains
                # this run's real flag - the only way that can happen is
                # if /bin/sh genuinely executed and printed it (nothing
                # legitimate ever serves it over HTTP).
                if FLAG and FLAG.encode() in body:
                    log_event("rce_impact_confirmed", path=path)

    def log_message(self, fmt: str, *args) -> None:  # noqa: A002
        pass  # default per-request stderr line is redundant with EVENT_LOG


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), ProxyHandler)
    server.serve_forever()
