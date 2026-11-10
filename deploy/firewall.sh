#!/bin/sh
# The firewall of a public machine, for the server. Written 2026-11-08 by Melanikus for AVPx Dedicated Server; the relay-only kind added
# 2026-11-09; SSH from the owner's address only, the same day (beta.2: players everywhere reach this machine, so nothing that isn't the
# game is open to them).
#
#   sh deploy/firewall.sh list OWNER.IP      the machine that runs the list and a relay (the first public one)
#   sh deploy/firewall.sh relay OWNER.IP     a machine that runs a relay only (a later region: no list, so no HTTPS and no certificate)
#
# OWNER.IP is the owner's own public IPv4 address, checked strictly before anything changes, by the same check the tester scripts use
# (deploy/tester-address.sh): four whole numbers from 0 to 255, written plainly, never 0.0.0.0 or 255.255.255.255.
#
# Everything coming in is refused, except:
#   TCP 22            SSH, from OWNER.IP only (keep it, or the machine can't be reached to fix it but by the       both kinds
#                     provider's own console)
#   TCP 443           the list (HTTPS), from anyone                                                           list only
#   UDP 27500         the relay's control port, from anyone                                                   both kinds
#   UDP 27501-27564   the relay's ports for joiners (the same range as relayPorts in /etc/avpx/settings.json)  both kinds
# Going out is allowed: the server answers, and the machine fetches its updates. No TCP 80: the list's certificate is its own,
# made on the machine from a key kept for good (deploy/README.md), so no certificate authority ever needs to reach it.
#
# SSH: the owner's rule goes in first, and only then is a rule that lets SSH in from anywhere taken out (the one deploy/README.md's
# section C makes), so the owner is never shut out halfway. If OWNER.IP is wrong, or the owner's address changes later, the way back in
# is the provider's own console, which doesn't come through the network: DigitalOcean's Recovery Console, or AWS Systems Manager's
# Session Manager. SSH over IPv6 is shut: an IPv4 rule opens nothing on IPv6.
#
# Run it as root, on a new public machine, and again whenever the owner's address changes (each run adds that address's rule; take an
# old address's out with ufw delete). It's safe to run again: ufw doesn't add a rule twice. Change the UDP range here and in the settings
# together. If the hosting company has its own firewall in front of the machine (AWS Lightsail, DigitalOcean and most others do), set
# the same there: SSH from OWNER.IP only, the rest from anyone, and nothing else.
#
# AVPX_UFW: only deploy/test-firewall.sh sets it, to a stand-in for ufw. On a real machine it's never set.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$here/tester-address.sh"

ufw=${AVPX_UFW:-ufw}
kind=${1:-}

case "$kind" in
  list|relay) ;;
  *) echo 'say which kind of machine, and the owner'"'"'s address: sh deploy/firewall.sh list OWNER.IP, or relay OWNER.IP'; exit 1 ;;
esac
[ "$#" -eq 2 ] || { echo 'say the kind of machine and the owner'"'"'s IPv4 address, and nothing else'; exit 1; }
owner=$(tester_address "$2") || { echo 'the owner'"'"'s address must be one plain IPv4 address, such as 203.0.113.9'; exit 1; }

"$ufw" default deny incoming
"$ufw" default allow outgoing
"$ufw" allow from "$owner" to any port 22 proto tcp comment 'SSH, from the owner only'
"$ufw" delete allow 22/tcp || echo 'there was no rule letting SSH in from anywhere to take out'
if [ "$kind" = list ]; then
  "$ufw" allow 443/tcp comment 'AVPx list (HTTPS)'
fi
"$ufw" allow 27500/udp comment 'AVPx relay control'
"$ufw" allow 27501:27564/udp comment 'AVPx relay, a port per joiner'
"$ufw" --force enable
"$ufw" status verbose
