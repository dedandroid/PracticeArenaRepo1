#!/bin/sh
set -e
# Bake this run's flag into a file that's reachable only via the real
# CVE-2021-41773/CVE-2021-42013 traversal-to-RCE chain - nothing in this
# app's normal config ever serves it over HTTP. Same "put the flag where
# only the exploit reaches it" convention as the other targets' DB rows.
#
# NOTE: the fallback default is deliberately NOT written inline as
# ${FLAG:-FLAG{...}} - a literal "}" inside a shell parameter-expansion
# default closes the expansion early regardless of whether FLAG is set,
# leaking a stray trailing "}" into the output. Two steps avoids it.
flag_value="${FLAG:-unset}"
if [ "$flag_value" = "unset" ]; then
    flag_value="FLAG{outdated_apache_cgi_rce_2026}"
fi
echo "$flag_value" > /flag.txt
chmod 644 /flag.txt
exec httpd-foreground
