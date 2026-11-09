#!/bin/sh
# Takes out the rules open-for-tester.sh made for one tester's address: the list (TCP 443) and the relay (UDP 27500 to 27564). Written
# 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/close-for-tester.sh <the tester's IPv4 address>     as root, on the test machine
#
# The address is checked as open-for-tester.sh checks it (deploy/tester-address.sh). Then ufw deletes exactly the two rules that script
# made, and nothing else. Close the same ports in the machine's provider's firewall too. The address isn't printed.
#
# AVPX_UFW: only deploy/test-open-for-tester.sh sets it, to a stand-in for ufw. On a real machine it's never set.
set -eu

ufw=${AVPX_UFW:-ufw}
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$here/tester-address.sh"

[ "$#" -eq 1 ] || { echo 'give exactly one address: the IPv4 address of the tester'; exit 1; }
address=$(tester_address "$1") || { echo 'that is not one IPv4 address, written plainly, so nothing was closed'; exit 1; }

"$ufw" delete allow from "$address" to any port 443 proto tcp
"$ufw" delete allow from "$address" to any port 27500:27564 proto udp
echo 'closed the list and the relay to the address given'
