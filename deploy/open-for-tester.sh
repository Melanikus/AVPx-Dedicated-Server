#!/bin/sh
# Opens the test machine's server to one tester's address, and to nobody else: the list (TCP 443) and the relay (UDP 27500 to 27564).
# Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/open-for-tester.sh <the tester's IPv4 address>      as root, on the test machine
#   sh deploy/close-for-tester.sh <the same address>             takes those rules out again
#
# WHY: the test machine is closed to everyone (deploy/README.md). To play the game against it, one person's address is let in, only to
# the server's own ports, and only until the test is over. The machine's provider's firewall (DigitalOcean's, Lightsail's) must let the
# same address through to the same ports too: that one is set in its web console.
#
# The address is checked strictly before anything changes (deploy/tester-address.sh): four whole numbers from 0 to 255, written plainly
# (no leading 0, no sign, no spaces), and not 0.0.0.0 or 255.255.255.255. Anything else is refused, so nothing but one address can ever
# reach ufw.
#
# The ports are the ones the settings in deploy/README.md use (list.port 443, controlPort 27500, relayPorts 27501-27564). Change them here,
# in close-for-tester.sh and there together. The address isn't printed or written anywhere by this script (the user's ruling: no IPs);
# ufw keeps it in its rules, which is what a rule is.
#
# AVPX_UFW: only deploy/test-open-for-tester.sh sets it, to a stand-in for ufw. On a real machine it's never set.
set -eu

ufw=${AVPX_UFW:-ufw}
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$here/tester-address.sh"

[ "$#" -eq 1 ] || { echo 'give exactly one address: the IPv4 address of the tester'; exit 1; }
address=$(tester_address "$1") || { echo 'that is not one IPv4 address, written plainly, so nothing was opened'; exit 1; }

"$ufw" allow from "$address" to any port 443 proto tcp comment 'avpx tester: the list'
"$ufw" allow from "$address" to any port 27500:27564 proto udp comment 'avpx tester: the relay'
echo 'opened the list (TCP 443) and the relay (UDP 27500-27564) to the one address given; close-for-tester.sh takes it out again'
