#!/bin/sh
# certbot --deploy-hook: copy the renewed certificate where the Gate reads it.
# The Gate notices the new file within 30 seconds; no restart needed.
set -eu
: "${RENEWED_LINEAGE:?run this as a certbot deploy hook}"
dest=/etc/lanternfish/tls

# Key first, then certificate: the Gate reloads when the certificate changes.
install -m 0640 -o root -g lanternfish "$RENEWED_LINEAGE/privkey.pem" "$dest/.privkey.pem.new"
mv -f "$dest/.privkey.pem.new" "$dest/privkey.pem"
install -m 0644 -o root -g lanternfish "$RENEWED_LINEAGE/fullchain.pem" "$dest/.fullchain.pem.new"
mv -f "$dest/.fullchain.pem.new" "$dest/fullchain.pem"
