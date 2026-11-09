# Putting the server on a machine

Written 2026-11-08 by Melanikus. This is for an ordinary Linux machine with Ubuntu LTS (24.04), such as an AWS Lightsail instance. **Nothing here has been run on a real machine yet.** Every step needs the machine's owner's word, and the owner buys the machine and the domain: nobody else ever handles payment details.

## What's in this folder

- **avpx.service:** the systemd service. It runs as its own user, `avpx`, with no rights but listening on port 443, and starts again by itself if it stops.
- **firewall.sh:** the firewall. In: SSH, TCP 443, TCP 80 (for the certificate only), UDP 27500 and UDP 27501-27564. Nothing else.
- **certificate-hook.sh:** run by certbot after each renewal. It puts a copy of the certificate where the service can read it.
- **settings.example.json:** the settings, as `/etc/avpx/settings.json` will hold them.

## Once, on a new machine (as root)

1. **Updates, and automatic security updates:**
   `apt update && apt full-upgrade -y && apt install -y unattended-upgrades ufw certbot`
2. **Node.js LTS, from nodejs.org, checked before it runs.**
   - Ubuntu's own Node package is an old version past its support, so it's not used.
   - Download the Linux x64 `.tar.xz` of the current LTS release from https://nodejs.org/dist/, with its `SHASUMS256.txt` and `SHASUMS256.txt.sig`.
   - Check the signature with the Node release team's keys (listed at https://github.com/nodejs/release-keys): `gpg --verify SHASUMS256.txt.sig SHASUMS256.txt`.
   - Then check the download: `sha256sum -c SHASUMS256.txt --ignore-missing`.
   - Only then unpack it to `/opt/node`, owned by root. `/opt/node/bin/node --version` should say the LTS version.
3. **The service's user,** which can't log in: `useradd --system --no-create-home --shell /usr/sbin/nologin avpx`
4. **The folders:**
   - `install -d -o root -g root -m 0755 /opt/avpx/releases`
   - `install -d -o root -g avpx -m 0750 /etc/avpx`
5. **The settings:** copy `settings.example.json` to `/etc/avpx/settings.json`, with `chown root:avpx` and `chmod 0640`. Then, in it:
   - **passKey:** make it on this machine with `openssl rand -hex 32` and put its 64 digits in. It's a secret: it's what proves a game's room to the list (PROTOCOL.md section 3, Passes). It never goes in the repository, a log or a message. The server refuses to start while the example's words are still there.
   - **host** in `list.relays`: the relay's DNS name, `virginia.relay.` and the domain, once the domain has a DNS record pointing it at this machine. The server refuses to start until it's a real name.
   - Change `relayPorts` there and in `firewall.sh` together, or neither.
   - A new version never touches this file: only `/opt/avpx` changes.
6. **The firewall:** `sh firewall.sh`. If the hosting company has a firewall of its own in front of the machine (Lightsail does), open the same ports there, and no others.
7. **The certificate,** once the domain points at the machine:
   - copy `certificate-hook.sh` to `/etc/letsencrypt/renewal-hooks/deploy/avpx.sh`, owned by root, with `chmod 0755`;
   - then `certbot certonly --standalone -d <the domain> --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/avpx.sh`.

   certbot answers Let's Encrypt's check on port 80 for a moment, and renews by itself twice a day when the certificate is near its end. The server takes up a renewed certificate within an hour, with no restart.
8. **The service:** copy `avpx.service` to `/etc/systemd/system/`, then:
   - `systemctl daemon-reload`;
   - `systemd-analyze security avpx`, to see what it's kept from;
   - `systemctl enable --now avpx`.

## Putting a new version on it

GitHub puts each version on the machine, with no key stored anywhere. It's done by GitHub Actions' OIDC, with a `production` environment the owner must approve each time. The plan (the workflow comes once the machine exists):

1. **Only a commit that passed every gate** in `GATES.md` can be deployed.
2. **The workflow asks AWS for a short-lived role by OIDC.** The role trusts only this repository's `production` environment, and may do one thing: run the deploy command on this one machine, through AWS Systems Manager. There's no SSH key and no stored password.
3. **On the machine, the command:**
   - fetches that exact commit's files and checks they're that commit;
   - unpacks them to `/opt/avpx/releases/<commit>`;
   - points `/opt/avpx/current` at them;
   - runs `systemctl restart avpx`;
   - checks the list answers on `https://<the domain>/v1/games?version=1`.

   If it doesn't answer, the command points `current` back at the version before, and restarts again.

## Adding a region later (not done yet)

The first version runs on one machine, `virginia` (AWS us-east-1), with the relay and the list. The code is ready for more relays; these steps aren't written as files yet:
- **The new machine** runs the same code with its own `region` and its own `passKey`, and no `list` in its settings.
- **Its firewall** opens only SSH and the relay's UDP ports. No TCP 443 or 80, and no certificate, because it has no list. `firewall.sh` and these steps have no relay-only version yet: that's owed.
- **The list's machine** gets one more entry in `list.relays`: the new region, its DNS name, its control port, and its `passKey`, copied over by hand, never through the repository. Then restart the service there.
- No game needs changing: games read the relays from `GET /v1/relays`.

## Reading what it says

`journalctl -u avpx`. Its lines are counts and times, never an address, a code, a token or a name.
