#!/bin/sh
# The machine's firewall, for the server. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
#
# Everything coming in is refused, except:
#   TCP 22            SSH, for the machine's owner (keep it, or the machine can't be reached to fix it)
#   TCP 443           the list (HTTPS)
#   TCP 80            only for the certificate: Let's Encrypt's check, which certbot answers while it renews
#   UDP 27500         the relay's control port
#   UDP 27501-27564   the relay's ports for joiners (the same range as relayPorts in /etc/avpx/settings.json)
# Going out is allowed: the server answers, and the machine fetches its updates.
#
# Run it once, as root, on a new machine: sh firewall.sh. It's safe to run again: ufw doesn't add a rule twice. Change the UDP range here
# and in the settings together. If the hosting company has its own firewall in front of the machine (AWS Lightsail and most others do),
# open the same ports there as well, and no others.
set -eu

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH, for the owner'
ufw allow 443/tcp comment 'AVPx list (HTTPS)'
ufw allow 80/tcp comment 'Let us Encrypt check while certbot renews'
ufw allow 27500/udp comment 'AVPx relay control'
ufw allow 27501:27564/udp comment 'AVPx relay, a port per joiner'
ufw --force enable
ufw status verbose
