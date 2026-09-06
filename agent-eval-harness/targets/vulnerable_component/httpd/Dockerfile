# The real, unpatched, pinned-vulnerable component - CWE-1104 needs an
# actual outdated dependency, not a simulation of one. This is stock
# httpd:2.4.49 (vulnerable to CVE-2021-41773 / CVE-2021-42013) with:
#   1. mod_cgid enabled (commented out by default)
#   2. <Directory /> changed from "Require all denied" to "Require all
#      granted"
# (2) matches Apache's own advisory wording exactly - "if files outside of
# the document root are NOT protected by the usual default configuration
# 'require all denied'" - and is the same change vulhub's own long-standing
# reference lab for this CVE makes to the stock config (verified against
# vulhub/vulhub's httpd/CVE-2021-42013/Dockerfile): the hardened default is
# not the vulnerable case this CVE is about, so reproducing it for real
# means deliberately relaxing that one directive, not leaving it as-is.
FROM httpd:2.4.49

RUN sed -i \
    -e 's/#LoadModule cgid_module modules\/mod_cgid.so/LoadModule cgid_module modules\/mod_cgid.so/' \
    -e 's/#Scriptsock cgisock/Scriptsock cgisock/' \
    /usr/local/apache2/conf/httpd.conf \
    && perl -0pi -e 's{<Directory />.*?</Directory>}{<Directory />\n    AllowOverride none\n    Require all granted\n</Directory>}s' \
        /usr/local/apache2/conf/httpd.conf \
    && echo 'Include conf/extra/status.conf' >> /usr/local/apache2/conf/httpd.conf

COPY status.conf /usr/local/apache2/conf/extra/status.conf
COPY htdocs/ /usr/local/apache2/htdocs/
COPY docker-entrypoint-wrapper.sh /usr/local/bin/docker-entrypoint-wrapper.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-wrapper.sh

ENTRYPOINT ["docker-entrypoint-wrapper.sh"]
CMD ["httpd-foreground"]
