#!/bin/sh
# Run by certbot each time it gets or renews the certificate (as its --deploy-hook). Written 2026-11-08 by Melanikus for AVPx Dedicated
# Server.
#
# certbot keeps the certificate where only root can read it. The server runs as avpx, so this copies the certificate and its key to
# /etc/avpx/tls/, readable by the avpx group and nobody else. The server looks at those files every hour and takes up new ones by itself,
# with no restart (list/https.js).
#
# certbot sets RENEWED_LINEAGE to the certificate's folder, such as /etc/letsencrypt/live/<the domain>. Install this as
# /etc/letsencrypt/renewal-hooks/deploy/avpx.sh, owned by root and not writable by anyone else.
set -eu

: "${RENEWED_LINEAGE:?certbot sets RENEWED_LINEAGE; this is only for certbot to run}"

install -d -o root -g avpx -m 0750 /etc/avpx/tls
install -o root -g avpx -m 0640 "$RENEWED_LINEAGE/fullchain.pem" /etc/avpx/tls/fullchain.pem.new
install -o root -g avpx -m 0640 "$RENEWED_LINEAGE/privkey.pem" /etc/avpx/tls/privkey.pem.new

# Both at once, so the server never reads a new certificate with an old key
mv -f /etc/avpx/tls/fullchain.pem.new /etc/avpx/tls/fullchain.pem
mv -f /etc/avpx/tls/privkey.pem.new /etc/avpx/tls/privkey.pem
