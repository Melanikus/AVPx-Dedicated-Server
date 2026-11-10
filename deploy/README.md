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
| `check-ubuntu-tools.sh` | For GitHub's deploy workflow: checks the curl, jq, gpg, unzip and sha256sum it uses are Ubuntu's own, unchanged |
| `get-aws-cli.sh` | For GitHub's deploy workflow: fetches the pinned AWS command line tool, checked by AWS's signature, its sha256 and its version. It refuses until its pins and `aws-cli-key.asc` are filled in (card #17) |
| `firewall.sh` | The firewall of a public machine, later: `list` for the list's machine (SSH, TCP 443, TCP 80 for the certificate, and the relay), `relay` for a relay-only one (SSH and the relay's UDP ports |
| `certificate-hook.sh` | For the public machine, later: certbot runs it after each renewal |
| `settings.example.json` | The settings, as `/etc/avpx/settings.json` holds them |
| `settings.relay-only.example.json` | The settings of a relay-only machine, a later region's: no list |
| `open-for-tester.sh`, `close-for-tester.sh`, `tester-address.sh` | A test machine opened to one tester's IPv4 address, and closed again |
| `test-*.sh` | The tests of the above, run by the "Deploy scripts" check |

## The first test machine, step by step (tonight)

This was the machine for what was SERVER-BLOCKERS.md's item 5: a first deploy to a machine nobody else can reach, passing the smoke test. That was shown on 2026-11-09, on a DigitalOcean machine by the path in the next section (History, at the end). **It's never open to the internet:** only your own address reaches it, and only for SSH. Nothing on it is public, so it needs **no domain and no Let's Encrypt certificate**: it gets a throwaway certificate of its own, which is all the smoke test needs. GitHub's deploy workflow refuses while anything is listed in SERVER-BLOCKERS.md, so this first deploy is done by your own hand, in the AWS console. Nothing automatic goes around the blockers.

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
3. **The firewall on the machine itself:** everything in refused, but SSH.
   ```
   ufw default deny incoming && ufw default allow outgoing && ufw allow 22/tcp && ufw --force enable
   ```
   - It lets SSH in from anywhere, and leaves narrowing that down to Lightsail's firewall from step B (your IP, plus Lightsail's browser terminal). The browser terminal connects from AWS's own addresses, so narrowing it here too would lock it out.
   - Everything else, the server's ports included, stays shut twice over: in Lightsail and here.
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
7. **Tell PO the result,** with the output. (A first deploy like this one is what SERVER-BLOCKERS.md asked for; it came off the list on 2026-11-09, shown on the DigitalOcean machine.)

### F. What you can do on the machine afterwards

- `systemctl status avpx-java` says whether it runs.
- `journalctl -u avpx-java` shows its log: counts and times only, never an address, a code, a token or a name.
- **To switch the test machine off:** in Lightsail, **Stop** (you still pay for its disk) or **Delete**. Its pass key and certificate go with it.

## A test machine anywhere (no AWS), such as a DigitalOcean droplet

The same test machine, on any host with Ubuntu 24.04 and a browser console, with **no Systems Manager, no cloud key, and nothing stored anywhere**: you run the deploy script yourself, by hand, in the console. It's the very script the SSM document wraps (`remote-deploy.sh`), so it does exactly the same checks.

### 1. The droplet

1. On DigitalOcean: **Create**, **Droplets**. Region **New York (NYC3)**. Image **Ubuntu 24.04 (LTS) x64**. Size **Basic**, the **2 GB** one. Name it `avpx-test-1`.
2. **Networking**, **Firewalls**, **Create Firewall**: inbound rules **SSH (TCP 22)** from **your own IP only**, and no other inbound rule; outbound as it is. Apply it to `avpx-test-1`.
3. Open the droplet, and choose **Access**, **Launch Droplet Console**. If the console won't connect through the firewall, use the **Recovery Console** there instead: it doesn't go through the network.

### 2. Set it up

**First run the Test build** (section 3, step 1), because step 8 below needs its commit.

Then in the console, as root (`sudo -i` if you aren't), do **section C above, steps 2 to 8**: the updates and tools, ufw (SSH only), the users `avpx` and `avpx-build`, the folders, the throwaway certificate, the settings, and the service. Step 9 holds too: the first deploy fetches the JDK.

**SSH from your address only, on the machine too** (two layers, not one; added 2026-11-09 from Third's nyc3 steps). Section C step 3 lets SSH in from anywhere, because Lightsail's browser terminal comes from AWS's own addresses. Here nothing needs that, so right after step 3, with `YOUR.IP` your own public address (the one in DigitalOcean's firewall):
```
ufw allow from YOUR.IP to any port 22 proto tcp && ufw delete allow 22/tcp && ufw status
```
The status must show port 22 from `YOUR.IP` only. If your address changes, both firewalls keep you out: come in by the **Recovery Console** (step 1.3, which doesn't go through the network), and put the new address in both.

**One change: name the region after where the machine really is.** Section C is written for AWS's us-east-1, in Virginia, so it says `virginia`. A droplet in DigitalOcean's nyc3 data centre (New York) is `nyc3`, DigitalOcean's own name for it, so players see where it is. In steps 6 and 7, then:
- **the certificate** is for `nyc3.relay.avpx.test`:
  ```
  cd /etc/avpx/tls && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout nyc3-key.pem -out nyc3-cert.pem -days 30 -subj "/CN=nyc3.relay.avpx.test" -addext "subjectAltName=DNS:nyc3.relay.avpx.test" -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" && chown root:avpx nyc3-*.pem && chmod 0640 nyc3-*.pem
  ```
- **the settings** say `"region": "nyc3"`, `"certFile": "/etc/avpx/tls/nyc3-cert.pem"` and `"keyFile": "/etc/avpx/tls/nyc3-key.pem"`, and their one relay is `{ "region": "nyc3", "host": "nyc3.relay.avpx.test", "port": 27500 }`.

On another host, use that data centre's own place the same way.

### 3. The first deploy, by hand

1. **On GitHub:** Actions, **Test build**, **Run workflow**, with the commit to deploy. Its summary shows three values: **commit**, **jarsSha256**, and **remote-deploy.sh's SHA-256**.
2. **In the console,** fetch exactly that commit with git, which names every file by its hash, so what arrives is that commit and nothing else. Put the commit in place of `COMMIT`:
   ```
   rm -rf /root/avpx-src && git init -q /root/avpx-src && cd /root/avpx-src && git fetch -q --depth 1 https://github.com/Melanikus/AVPx-Dedicated-Server.git COMMIT && git checkout -q FETCH_HEAD && git rev-parse HEAD
   ```
   The last line it prints must be the commit, exactly.
3. **Check the script** against the Test build's value:
   ```
   sha256sum deploy/remote-deploy.sh
   ```
   The 64 digits must be **remote-deploy.sh's SHA-256** from the summary, exactly. If they aren't, stop, and tell PO.
4. **Read it,** if you like (`less deploy/remote-deploy.sh`): it says in plain words what it does, step by step.
5. **Run it,** with the commit and jarsSha256 from the summary:
   ```
   sh deploy/remote-deploy.sh COMMIT JARS_SHA256
   ```
   It takes a few minutes the first time: it fetches the commit again as `avpx-build` (with no access to your settings or the certificate), fetches and checks the JDK, builds with no network, and runs every test. Then it checks the jars are the ones GitHub built, puts them in place, starts the service, and runs the smoke test.
6. **The result:**
   - it ends with `deploy: <commit> is in place, and healthy`, after the smoke test's lines, each `PASS`;
   - or it ends with a `deploy:` line that says why not. Nothing broken is left running.
   Copy everything it printed, and send it to PO.

### 4. Later, for the game test

To play the game against this machine from your own PC (PO gives the game's side of the steps), it's opened to **your own IP only**, in both firewalls:
- **DigitalOcean's firewall:** add inbound **TCP 443** and **UDP 27500-27564**, each from your IP only.
- **On the machine,** as root, from the fetched commit's folder: `sh deploy/open-for-tester.sh YOUR.IP`. It checks the address is one plain IPv4 address, opens exactly those two ports to it, and prints nothing of the address.
- **When the test is over:** `sh deploy/close-for-tester.sh YOUR.IP` takes those two rules out again, and the same ports come out of DigitalOcean's firewall.

Nothing is open to anyone else. **To be done with it:** destroy the droplet in DigitalOcean; its pass key and certificate go with it.

### 5. The access folder (version 2)

`/var/lib/avpx` holds who asked to play and what the owner decided (`java/src/avpx/access/AccessStore.java`). systemd makes it, the `avpx` user's, `0700` (the service's `StateDirectory`).
- **The server checks it at start and again about once a second:** it must still be `avpx`'s, with rights for nobody else. If it isn't, the server says why in its log (`journalctl -u avpx-java`) and stops. systemd starts it again every 5 s, and it refuses to start until the folder is put right, as root: `chown avpx:avpx /var/lib/avpx && chmod 0700 /var/lib/avpx`. Don't count on systemd to put it right by itself at the restart: it may give the folder back to `avpx`, but it may leave a changed mode as it is (that depends on its version, and only warns in its own log), so the `chmod` is what does it.
- **The owner's decisions** go in as files, made by the owner's own tools as the `avpx` user. The server takes them about once a second, on a thread of its own, and deletes each one once it's taken.
- **If taking them ever hangs for 60 s, or opening the store at start does** (a file swapped for a named pipe, or a disk that has stopped), the server says so and stops, and systemd starts it again. Before the relay listens at all, the server takes one turn of decisions, so one the owner left while it was down is in force from its first A1. At that start, anything under a decisions name that isn't a plain file is refused before it's opened.
- **Never edit `requests.json` by hand.** To clear a request, the owner's tools write a `forgotten` decision.

## Later: the public machine

When SERVER-BLOCKERS.md says `Nothing.`, GitHub's **Deploy** workflow (`.github/workflows/deploy.yml`) puts each version on the public machine, after you approve its `production` environment. It needs:
- **the domain,** with DNS names for the list and for `<region>.relay.<the domain>`, the region named after where the machine really is (`virginia` on AWS us-east-1, `nyc3` on DigitalOcean's nyc3);
- **a Let's Encrypt certificate covering both names,** so the smoke test's check against the relay's name passes: `certbot certonly --standalone -d <the list's name> -d <region>.relay.<the domain>`, with `certificate-hook.sh` as its deploy hook;
- **the firewall opened** to the game's ports (`sh deploy/firewall.sh list`, and the same in Lightsail's);
- **an IAM role** that trusts only this repository's `production` environment through GitHub's OIDC, and may only run `avpx-deploy` on the one machine (`ssm:SendCommand`, `ssm:GetCommandInvocation`). No Lightsail rights;
- **the repository variables** `AVPX_DEPLOY_ROLE_ARN`, `AVPX_DEPLOY_MACHINE` (the `mi-` id) and `AVPX_DEPLOY_REGION` (`us-east-1`). Until they're set, the workflow refuses.

**A new JDK every quarter:** Oracle's security updates come in January, April, July and October. When one lands, the check "The JDK is the newest Temurin 25" fails until get-jdk.sh's pinned lines move. The next deploy sees the machine's JDK isn't the pinned one, fetches the new one into a folder of its own, and moves the `/opt/avpx-jdk` link with the release.

## Adding a region: a relay-only machine

The first version runs on one machine, with the relay and the list. Each machine's region is named after where it really is, because players see that name: the test machine is `nyc3` (DigitalOcean's nyc3, in New York), and the AWS plan's machine is `virginia` (us-east-1). Each later region (Sao Paulo or Paris, say) is a machine that runs **a relay only**: the same server, with its own region and its own pass key, and no list. No game needs changing: games read the relays from `GET /v1/relays`. The list can know 16 relays at most.

1. **The machine:** Ubuntu 24.04 LTS, near its players. In the provider's own firewall, let in only SSH (TCP 22) from your own IP, for now.
2. **Set it up,** as root: section C's steps 2 to 5 exactly as written (the updates and tools, ufw with SSH only, the users `avpx` and `avpx-build`, the folders). **No certificate** (step 6): a relay-only machine has no list, so no HTTPS.
3. **Fetch the commit you'll deploy,** as in the DigitalOcean path's section 3, step 2, and check `remote-deploy.sh` against the Test build's value (step 3 there). The files below are in that folder, `/root/avpx-src`.
4. **Its settings:** `install -o root -g avpx -m 0640 deploy/settings.relay-only.example.json /etc/avpx/settings.json`, then change its two made-up values. The server refuses to start until both are real:
   - `region`: the new region's name, 1 to 16 small letters, digits and -, such as `saopaulo`;
   - `passKey`: 64 hex digits, made on this machine with `openssl rand -hex 32`. It's a secret: it never goes in a message, a log or the repository.
   - There's no `list` in it, and there mustn't be.
5. **The service and the deploy:** section C step 8, then `sh deploy/remote-deploy.sh COMMIT JARS_SHA256` (or Systems Manager, as in sections D and E).
   - **The health check,** `Smoke --installed`, sees the settings have no list and runs the relay's checks only: a whole game through the relay, and the pass for this region worked out again from the machine's own key. It ends with a `NOT RUN` line saying the list's checks weren't run. On a relay-only machine that's expected; on the list's machine it never shows.
6. **Its firewall, once the deploy is healthy:** `sh deploy/firewall.sh relay`. That's SSH and the relay's UDP ports (27500, and 27501-27564), and nothing else: no 443, no 80. Open UDP 27500-27564 in the provider's firewall too, and no other port.
7. **Its DNS name,** such as `saopaulo.relay.<the domain>`, points at the new machine.
8. **The list's machine** gets one more entry in the `list.relays` of its `/etc/avpx/settings.json`:
   ```
   { "region": "saopaulo", "host": "saopaulo.relay.<the domain>", "port": 27500, "passKey": "<the new machine's 64 digits>" }
   ```
   - The pass key is typed or pasted from one root terminal to the other by hand. Never through the repository, a message, a file left anywhere, or a log.
   - Then `systemctl restart avpx-java` there, and check `GET /v1/relays` lists the new region. Games can use it from then on.

## History

What happened on real machines, so a later reader knows what has been proved there and what hasn't.

- **2026-11-09, the first real deploy,** by hand, to the test machine in DigitalOcean nyc3 (New York). It stopped safely at the fetch, with nothing put in place, on two sandbox bugs the tests' stand-ins didn't model:
  - `InaccessiblePaths=/etc/letsencrypt` fails when that folder isn't there, and a test machine has no certbot;
  - the work folder was in `/tmp`, which the build steps can't see, since they have a `/tmp` of their own (`PrivateTmp`).
  - Both were fixed in b8f2caf, and the stand-in now fails the same way the machine did. git's warning about avpx-build's missing home went too: HOME is the work folder now.
- **2026-11-09, the second deploy,** of 6a885c9, passed. The pinned JDK was fetched and checked, the build ran with no network, the jars matched CI's, and `Smoke --installed` passed all 32 checks, healthy. No git warning.
- **2026-11-09, the region renamed, twice.** The machine had been set up as `virginia`, left over from the AWS plan, though it's in New York. It became `newyork`, then, at the owner's word, `nyc3`: DigitalOcean's own name for the data centre, so the name says exactly where the server is. Each name got a certificate of its own; `Smoke --installed --name nyc3.relay.avpx.test` passed 32 of 32. `virginia` stays for AWS us-east-1.
