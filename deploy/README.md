# Putting the server on a machine

Written 2026-11-08 by Melanikus; for the Java server only from 2026-11-09. It's for an ordinary Linux machine with Ubuntu 24.04 LTS, such as an AWS Lightsail instance.

**Nothing here has been run on a real machine yet.** Every step needs the machine's owner's word, and the owner buys the machine: nobody else ever handles payment details. Where a step is written from what the docs say and hasn't been seen to work, it says so.

## What's in this folder

| File | What it is |
|---|---|
| `avpx-java.service` | The systemd service. It runs as its own user, `avpx`, with no rights but listening on port 443, and starts again if it stops |
| `remote-deploy.sh` | What the machine runs to take one commit: it fetches it, builds it as a user with no rights, checks the jars are the tested ones, switches, health-checks, and rolls back on failure |
| `pull-deploy.sh` | What the machine runs, every 5 minutes, to fetch its own deploys: it asks GitHub for a deploy the owner approved, checks everything about it and main's blockers, and only then runs `remote-deploy.sh`. Nothing fetched runs as root |
| `avpx-pull.service`, `avpx-pull.timer` | The systemd service and timer that run `pull-deploy.sh` (section "The machine fetches its own deploys") |
| `check-blockers.sh` | Refuses every deploy while SERVER-BLOCKERS.md lists anything |
| `check-ubuntu-tools.sh` | For GitHub's deploy workflow: checks the curl, jq, gpg, unzip and sha256sum it uses are Ubuntu's own, unchanged |
| `firewall.sh` | The firewall of a public machine, later: `list OWNER.IP` for the list's machine (SSH from the owner's address only, TCP 443, and the relay), `relay OWNER.IP` for a relay-only one (SSH from the owner only, and the relay's UDP ports |
| `settings.example.json` | The settings, as `/etc/avpx/settings.json` holds them |
| `settings.relay-only.example.json` | The settings of a relay-only machine, a later region's: no list |
| `open-for-tester.sh`, `close-for-tester.sh`, `tester-address.sh` | A test machine opened to one tester's IPv4 address, and closed again |
| `test-*.sh` | The tests of the above, run by the "Deploy scripts" check |

## The first test machine, step by step (tonight)

This was the machine for what was SERVER-BLOCKERS.md's item 5: a first deploy to a machine nobody else can reach, passing the smoke test. That was shown on 2026-11-09, on a DigitalOcean machine by the path in the next section (History, at the end). **It's never open to the internet:** only your own address reaches it, and only for SSH. Nothing on it is public, so it needs **no domain and no Let's Encrypt certificate**: it gets a throwaway certificate of its own, which is all the smoke test needs. GitHub's deploy workflow refuses while anything is listed in SERVER-BLOCKERS.md, and so does the machine's own timer, so this first deploy is done by your own hand, in the machine's console. Nothing automatic goes around the blockers.

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
   apt update && apt full-upgrade -y && apt install -y unattended-upgrades git curl gpg jq
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
6. **The list's key, made once and kept, and its certificate** (the section "The list's key" below says why): for the made-up relay name `virginia.relay.avpx.test`, which no one can ever own (`.test` is reserved, RFC 6761):
   ```
   cd /etc/avpx/tls && (umask 027 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out list-key.pem) && openssl req -x509 -key list-key.pem -out list-cert.pem -days 36500 -subj "/CN=virginia.relay.avpx.test" -addext "subjectAltName=DNS:virginia.relay.avpx.test" -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" && chown root:avpx list-*.pem && chmod 0640 list-*.pem
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
       "certFile": "/etc/avpx/tls/list-cert.pem",
       "keyFile": "/etc/avpx/tls/list-key.pem",
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

### D. Deploy by hand

Exactly as on a droplet: the section "A test machine anywhere", step 3 (the Test build on GitHub, then `remote-deploy.sh` in the machine's own console, its SHA-256 checked first). There's no AWS Systems Manager route any more (the owner's ruling, 2026-11-09): a machine fetches its own deploys (the section "The machine fetches its own deploys"), and a test machine is deployed by hand.

### E. What you can do on the machine afterwards

- `systemctl status avpx-java` says whether it runs.
- `journalctl -u avpx-java` shows its log: counts and times only, never an address, a code, a token or a name.
- **To switch the test machine off:** in Lightsail, **Stop** (you still pay for its disk) or **Delete**. Its pass key and certificate go with it.

## A test machine anywhere (no AWS), such as a DigitalOcean droplet

The same test machine, on any host with Ubuntu 24.04 and a browser console, with **no Systems Manager, no cloud key, and nothing stored anywhere**: you run the deploy script yourself, by hand, in the console. It's the very script the machine's own timer runs for a deploy the owner approved (`remote-deploy.sh`, from `pull-deploy.sh`), so it does exactly the same checks.

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
- **the certificate** is for `nyc3.relay.avpx.test`: step 6 with `nyc3` in place of `virginia`, twice. Its key is made once, as there, and kept.
- **the settings** say `"region": "nyc3"`, and their one relay is `{ "region": "nyc3", "host": "nyc3.relay.avpx.test", "port": 27500 }`. The certificate's files are step 6's own, `list-cert.pem` and `list-key.pem`.

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

When SERVER-BLOCKERS.md says `Nothing.`, GitHub's **Deploy** workflow (`.github/workflows/deploy.yml`) records each version you approve (its `production` environment), and the machine's own timer fetches it and puts it in place (the section "The machine fetches its own deploys"). Nothing on GitHub reaches the machine. It needs:
- **no domain,** and no certificate from anyone else (the owner's rulings, 2026-11-09): players find the server by its line in the game's servers.cfg (#175), which holds its plain IPv4 address, one fingerprint of the list's key and the relay's id, and its name, so nothing a domain's next owner or a certificate authority does can move a player anywhere. The region is named after where the machine really is (`virginia` on AWS us-east-1, `nyc3` on DigitalOcean's nyc3);
- **the list's key, made once and kept,** and its certificate: section C step 6, and the section "The list's key" below;
- **its servers.cfg line,** once it runs: `java -jar /opt/avpx/current/avpx-smoke.jar --installed --servers-line "<its name>" <its public IPv4>` prints a `#` line naming the commit and the day, then the one line, `<address>  <fingerprint>  <name>` (TAKING-OVER.md, section 3 "Your own server", step 5, says what each field is), the fingerprint worked out on the machine from what it serves. Share those two lines as they are;
- **the firewall opened** to the game's ports, and SSH narrowed to your own address (`sh deploy/firewall.sh list YOUR.IP`), and the same in the provider's firewall: SSH from your address only, TCP 443 and UDP 27500-27564 from anyone, nothing else. After that, the way in if your address changes is a console of the provider's own that doesn't come through the network, such as DigitalOcean's Recovery Console. Lightsail's browser SSH comes from AWS's addresses and no longer gets through, so on a host with no such console, keep a second way in before you narrow SSH;
- **the `production` environment on GitHub** (the repository's Settings, Environments): you as its one required reviewer, and only `main` may deploy to it. The Deploy workflow's last job waits there for your approval, and the machine takes a deploy only if GitHub's record of that approval names you, by your login and your account's number;
- **the machine fetching its own deploys:** the section below, once.

### The machine fetches its own deploys

**What it is** (the owner's ruling, 2026-11-09: "nyc3 pulls its deploys"): a timer on the machine, every 5 minutes, runs `pull-deploy.sh` as root. It asks GitHub's public API, with no token, whether there's a new deploy for this machine, and takes one only if all of these hold:
- GitHub's own Actions recorded it (the Deploy workflow's last job), for this machine;
- no deployment before it named the same run: one approval, one deploy;
- its run was the Deploy workflow, started by hand from `main`, finished with success in its first attempt (a run done again with GitHub's "Re-run" never counts), and named `Deploy <this commit> to <this machine>`, so it wasn't a dry run, and was for this very commit and machine;
- you approved that run's `production` environment, by your login and your number;
- the commit is on `main`;
- `main`'s own SERVER-BLOCKERS.md lists nothing (checked before anything is built or installed).

Then it runs `remote-deploy.sh`, which builds the commit with no rights and no network, takes the jars only if they're GitHub's, switches, health-checks, and rolls back if anything fails. Each deployment, and each run, is taken once at most: `/var/lib/avpx-pull/taken` has a line for each, `<deployment> run <run>: <what became of it>`, and "taking" is written there before `remote-deploy.sh` starts. Nothing fetched from GitHub ever runs as root: the questions, the reading of the answers, the git fetch and `main`'s blockers check all run as `avpx-build`. Only the newest deployment is looked at: two Deploys within 5 minutes, and only the second is taken. To deploy again a commit that was refused, or an older one on purpose, start a new Deploy and approve it.

**One at a time:** the script holds `/var/lib/avpx-pull/lock` (flock) while it runs, so running it by hand while the timer's run is going stops at once, saying so. `remote-deploy.sh` holds a lock of its own, `/var/lib/avpx-deploy.lock`, so a deploy by hand while another is being put in place (the timer's, or a second by hand) stops at once too, and changes nothing. The other way round costs an approval: if the timer takes an approved deployment while a deploy by hand holds that lock, its `remote-deploy.sh` stops, the deployment is written down as "remote-deploy.sh refused or rolled back", and it's never taken again. Nothing is put in place, so it fails closed, but that deployment needs a new Deploy, approved again. So don't deploy by hand on a machine whose timer is on (stop `avpx-pull.timer` first).

**Installing it, once, as root** (from the commit a Test build named, with the two scripts' SHA-256 checked against its summary first, as in the by-hand deploy):
```
apt install -y jq
install -d -o root -g root -m 0755 /usr/local/lib/avpx-pull
install -o root -g root -m 0755 deploy/pull-deploy.sh deploy/remote-deploy.sh /usr/local/lib/avpx-pull/
install -o root -g root -m 0644 deploy/avpx-pull.service deploy/avpx-pull.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now avpx-pull.timer
```
- The service file names the machine (`nyc3`) on its `ExecStart` line: another machine changes that word.
- **A deploy never changes these two scripts.** What decides what runs as root is only ever what you installed: to change them, install them again by hand, the same way. So no answer from GitHub, and no commit, can change it.
- **To watch it:** `journalctl -u avpx-pull` says each look, and what it did. `/var/lib/avpx-pull/taken` lists each deployment taken, and what became of it.
- **To stop it:** `systemctl disable --now avpx-pull.timer`. The server runs exactly as before, and deploys are by hand again.
- It's asked about 12 times an hour, well under GitHub's 60 for an address with no token: the run and the approval are asked only when there's a new deployment.

### The list's key

**Why it's kept:** the game trusts the list by its key alone. The SHA-256 of the certificate's public key (its SubjectPublicKeyInfo, the "SPKI") is in every player's servers.cfg line, and the game checks nothing else of the certificate: not its name, its issuer or its dates. So the line holds for as long as the key does, and a server that outlives everyone who set it up keeps working.
- **Make the key once,** on the machine itself (section C step 6), and never copy it off. It's root's, readable by `avpx` only (0640, in `/etc/avpx/tls`, which `avpx-build` can't read).
- **A new certificate is made from the same key,** whenever one is wanted (another name, or just a newer one), with step 6's second command alone, `openssl req -x509 -key list-key.pem ...`, then `systemctl restart avpx-java`. The pin is the same, so the line is the same: check with `--servers-line` that it prints exactly what it printed before. The certificate's own dates don't matter to the game, and step 6 makes it good for 100 years anyway.
- **A new key is a new line,** which every player must be given again. Make one only if the old one may have been seen by anyone (the machine broken into, say), and then tell players to drop the old line.
- **Losing the machine loses the key,** and so the line: a new machine makes a new key, and a new line. That's the price of the key never being anywhere else.
- **To see the pin by hand:** `openssl x509 -in /etc/avpx/tls/list-cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`.

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
5. **The service and the deploy:** section C step 8, then `sh deploy/remote-deploy.sh COMMIT JARS_SHA256`, by hand, or the machine's own timer (the section "The machine fetches its own deploys", with this machine's region on its ExecStart line).
   - **The health check,** `Smoke --installed`, sees the settings have no list and runs the relay's checks only: a whole game through the relay, and the pass for this region worked out again from the machine's own key. It ends with a `NOT RUN` line saying the list's checks weren't run. On a relay-only machine that's expected; on the list's machine it never shows.
6. **Its firewall, once the deploy is healthy:** `sh deploy/firewall.sh relay YOUR.IP`. That's SSH from your address only and the relay's UDP ports (27500, and 27501-27564), and nothing else: no 443, no 80. Open UDP 27500-27564 in the provider's firewall too, and no other port.
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
