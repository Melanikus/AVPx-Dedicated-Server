#!/bin/sh
# The firewall of a public machine, for the server. Written 2026-11-08 by Melanikus for AVPx Dedicated Server; the relay-only kind added
# 2026-11-09.
#
#   sh deploy/firewall.sh list      the machine that runs the list and a relay (the first public one)
#   sh deploy/firewall.sh relay     a machine that runs a relay only (a later region: no list, so no HTTPS and no certificate)
#
# Everything coming in is refused, except:
#   TCP 22            SSH, for the machine's owner (keep it, or the machine can't be reached to fix it)          both kinds
#   TCP 443           the list (HTTPS)                                                                          list only
#   TCP 80            only for the certificate: Let's Encrypt's check, which certbot answers while it renews     list only
#   UDP 27500         the relay's control port                                                                  both kinds
#   UDP 27501-27564   the relay's ports for joiners (the same range as relayPorts in /etc/avpx/settings.json)    both kinds
# Going out is allowed: the server answers, and the machine fetches its updates.
#
# Run it once, as root, on a new public machine. It's safe to run again: ufw doesn't add a rule twice. Change the UDP range here and in
# the settings together. If the hosting company has its own firewall in front of the machine (AWS Lightsail, DigitalOcean and most
# others do), open the same ports there as well, and no others. A test machine uses neither kind: it stays closed (deploy/README.md).
#
# AVPX_UFW: only deploy/test-firewall.sh sets it, to a stand-in for ufw. On a real machine it's never set.
set -eu

ufw=${AVPX_UFW:-ufw}
kind=${1:-}

case "$kind" in
  list|relay) ;;
  *) echo 'say which kind of machine: sh deploy/firewall.sh list, or sh deploy/firewall.sh relay'; exit 1 ;;
esac
[ "$#" -eq 1 ] || { echo 'say only which kind of machine'; exit 1; }

"$ufw" default deny incoming
"$ufw" default allow outgoing
"$ufw" allow 22/tcp comment 'SSH, for the owner'
if [ "$kind" = list ]; then
  "$ufw" allow 443/tcp comment 'AVPx list (HTTPS)'
  "$ufw" allow 80/tcp comment 'Let us Encrypt check while certbot renews'
fi
"$ufw" allow 27500/udp comment 'AVPx relay control'
"$ufw" allow 27501:27564/udp comment 'AVPx relay, a port per joiner'
"$ufw" --force enable
"$ufw" status verbose
