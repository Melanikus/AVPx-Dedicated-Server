# What blocks putting the server in the wild

Written 2026-11-09 by Melanikus, at the user's word: "This is a server in the wild. Tao 1 and 3. We CANNOT get it wrong."

**How this file works.** Every deploy workflow, now or later, and every way a machine fetches its own deploys (such as the pull route nyc3 is to use, by PO's ruling of 2026-11-09), runs `sh deploy/check-blockers.sh`, from main as it is at that moment, **before anything is built or installed**, and as a user with no rights over the machine. It refuses to go on while anything is listed under the heading below. (deploy.yml's first job checks main's list before its build job; the pull route fetches main into a fresh folder as `avpx-build`, and runs that main's check there, before remote-deploy.sh or anything of root's.) Only the word `Nothing.`, on its own, lets a deploy run. It also refuses:
- an empty list;
- a missing heading, or the heading twice;
- a file cut short, without its last line.

An item comes off the list only when it's done, in the commit that shows it, never to let a deploy through. deploy/test-check-blockers.sh proves the refusals work; GATES.md's "Server blockers" check runs it.

**A test machine isn't the wild.** A machine nobody but the owner can reach is a test machine: its provider's firewall (DigitalOcean's, Lightsail's) and ufw on the machine itself both let in the owner's own address, and nothing else. It's deployed by hand, with `deploy/remote-deploy.sh` in its console (deploy/README.md, "A test machine anywhere"). That script doesn't read this file, so this rule is what says when that may happen. The list below doesn't block a test machine, and the first deploy below was one. **The moment either firewall lets in anything else, the machine is in the wild,** and everything listed below blocks it again, until it's closed or destroyed. The one exception is named below, for nyc3 alone; nothing else is one.
- **By name: nyc3, open to everyone who has a key** (the owner's rulings, 2026-11-10: "Open nyc3 to everyone now", "No more IP blocks", and "'Open to everyone' WHO HAS A KEY!"). It replaced the self-test's rule of the day before (PO's ruling R2, 2026-11-09), under which both firewalls admitted the owner's address alone. That rule failed him whenever his VPN was on, since a VPN gives him an address that isn't his line's. **nyc3 is in the wild,** running protocol 2 while items 1 to 7 below still stand. Both of its firewalls, DigitalOcean's in front of it and ufw on the machine, let in every address on exactly four ports: TCP 22, TCP 443, UDP 27500-27564 and UDP 51821. **What anyone gets there is decided by a key they hold, never by their address,** and this rule covers nyc3 only while all of this holds:
  - **The relay (UDP 27500-27564) serves approved players alone.** nyc3's settings say `"protocol": 2`, and a version 1 message to a version 2 relay is refused (RelayCore.java), so nothing goes in the clear. Before anything else, a stranger gets only a cookie to send back, and never more bytes than they sent (CRYPTO.md, the table's row 8). Handshake A then refuses a key that isn't an approved player's, compared by its whole SHA-384 (Approvals.java), before any secret is worked out with that key (refusal 22, CRYPTO.md section 6). A host gets the pass that puts a game on the list only over the sealed channel that A opens.
  - **The list (TCP 443) speaks only TLS, and a stranger with no key gets nothing that is a player's.** What it can ask for:
    - the relays;
    - the relay's two public keys;
    - an access request's answer, the state of the keys it sent. That takes the public keys themselves, which nothing a stranger can reach shows: a listing holds only their hash (AccessRequests.java);
    - the games' list.

    Putting a game on the list needs the relay's pass (above). Until the card "the games list for approved keys only" is built, `GET /v1/games` shows anyone the running games' names, levels and player counts, never an address (Routes.java). A flood of access requests is item 7's, and that item stands.
  - **SSH (TCP 22) takes keys alone.** The owner chose this after his own VPN shut him out of an SSH open to his address alone: "I always run a VPN (Except now, because of you) SSH only for now", and "BOTH SSH and IP whitelist are a bit too much now". sshd answers anyone who reaches it, so nyc3's steps check each of these:
    - sshd takes keys alone: `sshd -T` shows `passwordauthentication no`, `kbdinteractiveauthentication no` and `permitrootlogin prohibit-password`, set in `/etc/ssh/sshd_config.d/`;
    - ufw's rule for it is `LIMIT` (v4 and v6), so one address trying again and again is held off;
    - Ubuntu's unattended-upgrades is on, so sshd's own fixes land by themselves.

    The admin tunnel stays the planned replacement: once it works end to end for the owner, SSH answers only inside it.
  - **UDP 51821, the admin tunnel (`wg-admin`):** WireGuard answers nothing to a packet it can't authenticate with a key it holds. A stranger there gets no answer at all, and learns nothing, not even that something is there.
  - **Nothing else is let in,** in either firewall: no other port, and no rule for one address. Nothing needs one now, and an address isn't who someone is: a VPN's exit is shared by all its customers.
  - **Who changes the firewalls:**
    - DigitalOcean's firewall is PO's, changed only through DigitalOcean's API, with the owner's token, which is never written anywhere in this repository;
    - ufw is PO's too, over SSH.

    nyc3's steps check both firewalls before anything changes on the machine, and stop on any other port or rule.
  - **deploy/firewall.sh is never run on nyc3:** it narrows SSH to one address, which would shut out whoever reaches nyc3 through a VPN.

  **What the owner's ruling takes on, for nyc3 alone:** the items still standing below, 2, 3, 4, 6's other two compares, and 7. A stranger with no key reaches the TLS handshake, the list's reading of a request, the relay's cookie round, and handshake A's first message up to the approval check. No independent reviewer has read that code yet (item 2). This rule names nyc3 and no other machine, and it ends when nyc3 is destroyed or the owner rules again.

## Taken off the list, and what showed each was done

- **A first deploy, to a test machine nobody else can reach, passes the smoke client.** Done 2026-11-09, on the test machine in DigitalOcean nyc3 (New York), region `nyc3`. While it ran, its DigitalOcean firewall let in only SSH, from the owner's own address. The second run, of 6a885c9, by hand with `deploy/remote-deploy.sh`, ended `in place, and healthy`, with `Smoke --installed` 32 of 32. Written up on issue #15, and in deploy/README.md's History. It showed neither deploy.yml nor a machine taking its own deploys (the pull route, which has since replaced the Systems Manager route): item 5 below stands in their way.
- **The deploy's AWS command line tool is pinned (#17)**, the old item 5. Taken off 2026-11-09, by the owner's ruling, in the owner's words: "Remove it; item 5 guards the pull route". The commit that shows it is the one that builds the pull route (deploy/pull-deploy.sh): it removes the AWS Systems Manager route whole, with get-aws-cli.sh and its test, the SSM document and its maker, and deploy.yml's job that ran aws. No AWS tool runs anywhere in a deploy now, so there's nothing left to pin. **Item 5 below takes its place, and keeps every deploy blocked** until the route that replaces it is built, tested and freshly reviewed. If the AWS route ever comes back, #17 comes back with it.
- **One address can't keep other players from starting a game.** Added and taken off 2026-11-10, in the commit that shows it. Every
  handshake datagram is spent from its address's own share before anything is hashed, and a COOKIE_ASK from its address and port's
  share before everyone's (java/src/avpx/v2/SealedRelay.java, "ONE SOURCE'S SHARE"; CRYPTO.md section 17's rows). What shows it:
  SealedRelayTest's "one source's share" test, and its take-out rows in java/tools/takeouts.txt, each noticed.

## For later: before a second region or a second operator

Not blocking a deploy, by PO's ruling for the owner (2026-11-09). With one region and one operator, the game ships with what it must trust: the relay's id and the list's key (item 1 below). That stops working with a second region or a second operator, because the game can no longer ship every relay's id, and a player needs a signed answer from someone they already trust. So, before there's a second of either:
- **CRYPTO.md section 12's signed files are built:** the signed manifest, the signed relays directory, and the list's signed answers, with section 12's signers and ML-DSA's context (5.1 point 16).

## Blocking a deploy

1. Protocol version 2 (CRYPTO.md) is built end to end, in this server and in the game, as beta.2 uses it (PO's ruling for the owner, 2026-11-09): handshake A (pqIK, approved players only) and handshake B, the sealed control channel and sealed game datagrams. In place of CRYPTO.md section 12's signed files, beta.2 trusts two things the game ships with. The first is each relay's id, pinned in its line of the game's servers.cfg (#175), which the keys `GET /v1/relay-keys` gives are checked against. The second is the list's certificate key, pinned by its SPKI, so the list is reached only over TLS to that key. Section 12 is its own item, above this list, for later. Version 1, with its messages in the clear, is never put in the wild.
2. The independent security review (#2) is done, and every finding is fixed.
3. Every gate is green and required on main, Snyk included, with branch protection that holds for administrators too.
4. The review of the post-quantum libraries' source (#10) is done.
5. The pull route, the one way a machine takes its deploys (the owner's ruling, 2026-11-09: "nyc3 pulls its deploys"), is built, tested and freshly reviewed. That's `deploy/pull-deploy.sh` with its timer, deploy.yml's record job, and `deploy/test-pull-deploy.sh` passing on GitHub's runner. A reviewer who didn't write it reads all of it as hostile and finds nothing open. It took the old item 5's place (above, "Taken off the list").
6. Every identity a machine compares is the whole SHA-384, 48 bytes, never the 16-byte fingerprint people read (CRYPTO.md section 8): the approved players at the relay, each relay's keys against the relay id the game holds for it (its servers.cfg line, #175; or, for tests, -dev's `RelayKey` line in AliensVsPredator.cfg's `[Network]`), and the listing's host against handshake B's keys. It comes off when the last of the three is built and its vectors pass.
7. Before the list's address is given to anyone but the owner's testers, a flood of access requests can't lock new players out (Secondary's review of the access store, finding 1.1). The code (f1858a8) gives the owner a decision that forgets a waiting or refused request. It limits new requests to 5 a day from one address and 10 a day from one network (an IPv4 address's first 24 bits). And it keeps a crowd of more than 10,000 addresses from resetting the access call's limits. Each day's bucket starts full and fills once more in the day, and every bucket starts again when the address hasher's daily secret changes. So one address adds at most 10 a day and one network 20: at most 300 and 600 in the 30 days a waiting request stays, so neither fills the 1,000 waiting places alone (AccessLimits.java's header has the arithmetic). Filling them now takes 100 networks at once, or 50 over a day, where before it took one address about 4 days. A large enough botnet can still fill them: a key costs nothing to make, so no limit of the server's alone tells a junk request from a real one. It comes off when PO and Secondary agree that what's left is acceptable for a public list, or when something else closes it, such as an invitation or a proof of work.

End of the list.
