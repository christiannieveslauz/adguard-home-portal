#!/bin/sh
set -e
: "${ADMIN_URL:=}"
mkdir -p /certs
if [ ! -s /certs/portal.crt ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=Sitio bloqueado por AdGuard Home/O=AdGuard Home Portal" \
    -keyout /certs/portal.key -out /certs/portal.crt >/dev/null 2>&1
fi
ADMIN_URL="${ADMIN_URL%/}"
sed -i "s#__ADMIN_URL__#${ADMIN_URL}#g" /usr/share/nginx/html/index.html
