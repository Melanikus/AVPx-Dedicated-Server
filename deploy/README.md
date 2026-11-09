# Putting the server on a machine

Written 2026-11-08 by Melanikus; for the Java server only from 2026-11-09. It's for an ordinary Linux machine with Ubuntu 24.04 LTS, such as an AWS Lightsail instance.

**Nothing here has been run on a real machine yet.** Every step needs the machine's owner's word, and the owner buys the machine: nobody else ever handles payment details. Where a step is written from what the docs say and hasn't been seen to work, it says so.

## What's in this folder

| File | What it is |
|---|---|
| `avpx-java.service` | The systemd service. It runs as its own user, `avpx`, with no rights but listening on port 443, and starts again if it stops |
| `remote-deploy.sh` | What the machine runs to take one commit: it fetches it, builds it as a user with no rights, checks the jars are the tested ones, switches, health-checks, and rolls back on failure |
| `avpx-deploy.ssm.json` | The same script as an AWS Systems Manager document, `avpx-deploy`, made from `remote-deploy.sh` by `make-ssm-document.sh` |
| `check-blockers.sh` | Refuses every deploy while SERVER-BLOCKERS.md lists anything |
| `firewall.sh` | The firewall for the public machine, later: SSH, TCP 443, TCP 80 for the certificate, and the relay's UDP ports |
| `certificate-hook.sh` | For the public machine, later: certbot runs it after each renewal |
| `settings.example.json` | The settings, as `/etc/avpx/settings.json` holds them |
| `test-*.sh` | The tests of the above, run by the "Deploy scripts" check |

## The first test machine, step by step (tonight)

This is the machine for SERVER-BLOCKERS.md's item 5: a first deploy to a machine nobody else can reach, passing the smoke test. **It's never open to the internet:** only your own address reaches it, and only for SSH. Nothing on it is public, so it needs **no domain and no Let's Encrypt certificate**: it gets a throwaway certificate of its own, which is all the smoke test needs. GitHub's deploy workflow refuses while anything is listed in SERVER-BLOCKERS.md, so this first deploy is done by your own hand, in the AWS console. Nothing automatic goes around the blockers.

### A. Buy the machine (Lightsail)

1. Go to **lightsail.aws.amazon.com**. Choose **Create instance**.
2. **Instance location:** change the region to **Virginia (us-east-1)**. Keep the zone it offers.
3. **Platform:** Linux/Unix. **Blueprint:** "OS Only", then **Ubuntu 24.04 LTS**.
4. **Plan:** the **2 GB** one (2 GB memory). It's around US$12 a month; check the price shown before you buy.
5. **Name it** `avpx-test`, and choose **Create instance**.
6. Wait until it says **Running**.

### B. Close it to everyone but you

1. Open the instance, then the **Networking** tab.
2. Under **IPv4 Firewall**:
   - delete every rule except SSH;
   - edit the SSH rule: **Restrict to IP address**, and put in your own public IP (searching "what is my IP" shows it). Leave **Allow Lightsail browser SSH** ticked, so the browser terminal in step C still works.
3. Under **IPv6 Firewall**: delete every rule, or turn IPv6 networking off.
4. Nothing else is opened: not 443, not 80, not the relay's UDP ports. The server talks only to itself on this machine.

### C. Set the machine up (once, in the browser terminal)

1. On the instance's page, choose **Connect using SSH**. A terminal opens in the browser. Become root: `sudo -i`.
2. **Updates, and the tools the deploy uses:**
   ```
   apt update && apt full-upgrade -y && apt install -y unattended-upgrades git curl gpg
   ```
3. **The firewall on the machine itself,** the same as Lightsail's. Put your IP in place of `YOUR.IP`:
   ```
   ufw default deny incoming && ufw default allow outgoing && ufw allow from YOUR.IP to any port 22 proto tcp && ufw --force enable
   ```
   Lightsail's browser terminal reaches the machine through AWS's own addresses, so if it stops connecting after this, also run `ufw allow 22/tcp`. Lightsail's firewall from step B still holds SSH to your address. (Not yet checked on a real machine.)
4. **Two users with no rights, which can't log in:**
   ```
   useradd --system --no-create-home --shell /usr/sbin/nologin avpx
   useradd --system --no-create-home --shell /usr/sbin/nologin avpx-build
   ```
   - `avpx` runs the server.
   - `avpx-build` fetches and builds each new version, and can't read the settings or the certificate.
5. **The folders:**
   ```
   install -d -o root -g root -m 0755 /opt/avpx /opt/avpx/releases
   install -d -o root -g avpx -m 0750 /etc/avpx /etc/avpx/tls
   ```
6. **A throwaway certificate,** for the made-up relay name `virginia.relay.avpx.test`, which never leaves this machine:
   ```
   cd /etc/avpx/tls && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout test-key.pem -out test-cert.pem -days 30 -subj "/CN=virginia.relay.avpx.test" -addext "subjectAltName=DNS:virginia.relay.avpx.test" -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" && chown root:avpx test-*.pem && chmod 0640 test-*.pem
   ```
7. **The settings.** Make a pass key first, with `openssl rand -hex 32`. Then write `/etc/avpx/settings.json`, with the 64 digits it printed in place of `PASS_KEY`:
   ```
   {
     "region": "virginia",
     "passKey": "PASS_KEY",
     "relayAddress": "0.0.0.0",
     "controlPort": 27500,
     "relayPorts": "27501-27564",
     "logFile": "",
     "list": {
       "address": "0.0.0.0",
       "port": 443,
       "certFile": "/etc/avpx/tls/test-cert.pem",
       "keyFile": "/etc/avpx/tls/test-key.pem",
       "relays": [{ "region": "virginia", "host": "virginia.relay.avpx.test", "port": 27500 }]
     }
   }
   ```
   Then `chown root:avpx /etc/avpx/settings.json && chmod 0640 /etc/avpx/settings.json`. The pass key is a secret: it never goes in a message, a log or the repository.
8. **The service,** from the commit you'll deploy (step E gives it). Put that commit in place of `COMMIT`:
   ```
   curl -fsS --proto '=https' -o /etc/systemd/system/avpx-java.service https://raw.githubusercontent.com/Melanikus/AVPx-Dedicated-Server/COMMIT/deploy/avpx-java.service
   systemctl daemon-reload && systemctl enable avpx-java
   ```
   Read the file before going on (`cat /etc/systemd/system/avpx-java.service`). It doesn't start yet: the first deploy starts it.
9. **The JDK:** nothing to do. The first deploy sees there's none, and fetches the one the commit pins, checked by its signature, its sha256 and its version.

### D. Let AWS Systems Manager reach it (once)

Systems Manager runs the deploy on the machine for you, with no SSH key and no password stored anywhere.

1. In the AWS console, go to **Systems Manager**, region **us-east-1**. Then **Fleet Manager**, **Hybrid activations**, **Create activation**.
2. **Instance limit:** 1. **IAM role:** let it create the default one (its only policy is `AmazonSSMManagedInstanceCore`). **Expiry:** 1 day. **Default instance name:** `avpx-test`. Create it.
3. AWS shows an **Activation code** and an **Activation ID**, once. Keep them for the next step only. They're not needed after it, and they expire in a day.
4. In the machine's terminal, as root, put them in place of `CODE` and `ID`:
   ```
   snap list amazon-ssm-agent || snap install amazon-ssm-agent --classic
   snap stop amazon-ssm-agent
   /snap/amazon-ssm-agent/current/amazon-ssm-agent -register -code "CODE" -id "ID" -region us-east-1
   snap start amazon-ssm-agent
   ```
   (Written from AWS's documents; not yet seen on this machine.)
5. Back in **Fleet Manager**, the machine appears as a **managed node**, with an id that starts `mi-`. Note it down.
6. **The document:** **Systems Manager**, **Documents**, **Create document**, **Command or Session**.
   - Name it `avpx-deploy`, and choose JSON.
   - Paste in the whole of `deploy/avpx-deploy.ssm.json` from the commit you'll deploy, then create it.
   - Read it first: it's `remote-deploy.sh`, word for word, with the two values it takes. AWS itself refuses any value not shaped like a commit or a SHA-256.

### E. Build, then deploy by hand

1. **On GitHub:** Actions, **Test build**, **Run workflow**. Put in the commit to deploy: the newest commit of `main` that has passed every check. It only builds, and can't reach AWS.
2. When it's done, its summary shows two lines, **commit** and **jarsSha256**. Copy both.
3. **In the AWS console:** **Systems Manager**, **Run Command**, **Run command**. Search for `avpx-deploy` ("Owned by me"), and choose it.
4. **Command parameters:** paste the **commit** and the **jarsSha256**.
5. **Targets:** **Choose instances manually**, and tick the `mi-` machine. Under **Output options**, untick the S3 bucket. Then **Run**.
6. Wait for **Success** or **Failed**. It takes a few minutes: the machine fetches the commit, fetches the JDK the first time, builds, and runs every test. Then open the machine's line, **View output**:
   - **Success** ends with `deploy: <commit> is in place, and healthy`, after the smoke test's lines, each `PASS`.
   - **Failed** says why on its last `deploy:` line. Nothing broken is left running: the service is stopped, or the release before is back.
7. **Tell PO the result,** with the output. If it passed, that's item 5 of SERVER-BLOCKERS.md shown, which PO takes off the list.

### F. What you can do on the machine afterwards

- `systemctl status avpx-java` says whether it runs.
- `journalctl -u avpx-java` shows its log: counts and times only, never an address, a code, a token or a name.
- **To switch the test machine off:** in Lightsail, **Stop** (you still pay for its disk) or **Delete**. Its pass key and certificate go with it.

## Later: the public machine

When SERVER-BLOCKERS.md says `Nothing.`, GitHub's **Deploy** workflow (`.github/workflows/deploy.yml`) puts each version on the public machine, after you approve its `production` environment. It needs:
- **the domain,** with DNS names for the list and for `virginia.relay.<the domain>`;
- **a Let's Encrypt certificate covering both names,** so the smoke test's check against the relay's name passes: `certbot certonly --standalone -d <the list's name> -d virginia.relay.<the domain>`, with `certificate-hook.sh` as its deploy hook;
- **the firewall opened** to the game's ports (`firewall.sh`, and the same in Lightsail's);
- **an IAM role** that trusts only this repository's `production` environment through GitHub's OIDC, and may only run `avpx-deploy` on the one machine (`ssm:SendCommand`, `ssm:GetCommandInvocation`). No Lightsail rights;
- **the repository variables** `AVPX_DEPLOY_ROLE_ARN`, `AVPX_DEPLOY_MACHINE` (the `mi-` id) and `AVPX_DEPLOY_REGION` (`us-east-1`). Until they're set, the workflow refuses.

**A new JDK every quarter:** Oracle's security updates come in January, April, July and October. When one lands, the check "The JDK is the newest Temurin 25" fails until get-jdk.sh's pinned lines move. The next deploy sees the machine's JDK isn't the pinned one, fetches the new one into a folder of its own, and moves the `/opt/avpx-jdk` link with the release.

## Adding a region later (not done yet)

The first version runs on one machine, `virginia` (us-east-1), with the relay and the list. The code is ready for more relays; these steps aren't written as files yet:
- **The new machine** runs the same server with its own `region` and its own `passKey`, and no `list` in its settings.
- **Its firewall** opens only the relay's UDP ports. `firewall.sh` has no relay-only version yet: that's owed.
- **The list's machine** gets one more entry in `list.relays`: the new region, its DNS name, its control port and its `passKey`, copied over by hand, never through the repository.
- No game needs changing: games read the relays from `GET /v1/relays`.
