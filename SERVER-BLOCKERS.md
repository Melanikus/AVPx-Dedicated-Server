# What blocks putting the server in the wild

Written 2026-11-09 by Melanikus, at the user's word: "This is a server in the wild. Tao 1 and 3. We CANNOT get it wrong."

**How this file works.** Every deploy workflow, now or later, and every way a machine fetches its own deploys (such as the pull route nyc3 is to use, by PO's ruling of 2026-11-09), runs `sh deploy/check-blockers.sh` as its first step. That step refuses to go on while anything is listed under the heading below. Only the word `Nothing.`, on its own, lets a deploy run. It also refuses:
- an empty list;
- a missing heading, or the heading twice;
- a file cut short, without its last line.

An item comes off the list only when it's done, in the commit that shows it, never to let a deploy through. deploy/test-check-blockers.sh proves the refusals work; GATES.md's "Server blockers" check runs it.

**A test machine isn't the wild.** A machine nobody but the owner can reach is a test machine: its provider's firewall (DigitalOcean's, Lightsail's) and ufw on the machine itself both let in the owner's own address, and nothing else. It's deployed by hand, with `deploy/remote-deploy.sh` in its console (deploy/README.md, "A test machine anywhere"). That script doesn't read this file, so this rule is what says when that may happen. The list below doesn't block a test machine, and the first deploy below was one. **The moment either firewall lets in anything else, the machine is in the wild,** and everything listed below blocks it again, until it's closed or destroyed.
- **By name: the owner's version 2 self-test, 2026-11-14/15** (PO's ruling R2 for the owner, 2026-11-09). nyc3 runs protocol 2 for the owner's two PCs while items 1 to 7 still stand. It's covered by this rule **only while DigitalOcean's firewall and ufw on nyc3 both admit the owner's address alone**. Its steps check both before anything changes, and stop if anything else gets in. ufw's SSH rule is narrowed to the owner too: deploy/README.md's set-up lets SSH in from anywhere there, leaving the narrowing to the provider's firewall alone.

## Taken off the list, and what showed each was done

- **A first deploy, to a test machine nobody else can reach, passes the smoke client.** Done 2026-11-09, on the test machine in DigitalOcean nyc3 (New York), region `nyc3`. While it ran, its DigitalOcean firewall let in only SSH, from the owner's own address. The second run, of 6a885c9, by hand with `deploy/remote-deploy.sh`, ended `in place, and healthy`, with `Smoke --installed` 32 of 32. Written up on issue #15, and in deploy/README.md's History. It doesn't show the Systems Manager route or deploy.yml's send: item 5 below is part of what still stands in their way.

## For later: before a second region or a second operator

Not blocking a deploy, by PO's ruling for the owner (2026-11-09). With one region and one operator, the game ships with what it must trust: the relay's id and the list's key (item 1 below). That stops working with a second region or a second operator, because the game can no longer ship every relay's id, and a player needs a signed answer from someone they already trust. So, before there's a second of either:
- **CRYPTO.md section 12's signed files are built:** the signed manifest, the signed relays directory, and the list's signed answers, with section 12's signers and ML-DSA's context (5.1 point 16).

## Blocking a deploy

1. Protocol version 2 (CRYPTO.md) is built end to end, in this server and in the game, as beta.2 uses it (PO's ruling for the owner, 2026-11-09): handshake A (pqIK, approved players only) and handshake B, the sealed control channel and sealed game datagrams. In place of CRYPTO.md section 12's signed files, beta.2 trusts two things the game ships with. The first is each relay's id, pinned in its line of the game's servers.cfg (#175), which the keys `GET /v1/relay-keys` gives are checked against. The second is the list's certificate key, pinned by its SPKI, so the list is reached only over TLS to that key. Section 12 is its own item, above this list, for later. Version 1, with its messages in the clear, is never put in the wild.
2. The independent security review (#2) is done, and every finding is fixed.
3. Every gate is green and required on main, Snyk included, with branch protection that holds for administrators too.
4. The review of the post-quantum libraries' source (#10) is done.
5. The deploy's AWS command line tool is pinned (#17): `deploy/get-aws-cli.sh` has its version, its sha256 and AWS's key fingerprint, and `deploy/aws-cli-key.asc` is there. Until then the script refuses, and so would a deploy.
6. Every identity a machine compares is the whole SHA-384, 48 bytes, never the 16-byte fingerprint people read (CRYPTO.md section 8): the approved players at the relay, each relay's keys against the relay id the game holds for it (its servers.cfg line, #175; or, for tests, -dev's `RelayKey` line in AliensVsPredator.cfg's `[Network]`), and the listing's host against handshake B's keys. It comes off when the last of the three is built and its vectors pass.
7. Before the list's address is given to anyone but the owner's testers, a flood of access requests can't lock new players out (Secondary's review of the access store, finding 1.1). The code (f1858a8) gives the owner a decision that forgets a waiting or refused request. It limits new requests to 5 a day from one address and 10 a day from one network (an IPv4 address's first 24 bits). And it keeps a crowd of more than 10,000 addresses from resetting the access call's limits. Each day's bucket starts full and fills once more in the day, and every bucket starts again when the address hasher's daily secret changes. So one address adds at most 10 a day and one network 20: at most 300 and 600 in the 30 days a waiting request stays, so neither fills the 1,000 waiting places alone (AccessLimits.java's header has the arithmetic). Filling them now takes 100 networks at once, or 50 over a day, where before it took one address about 4 days. A large enough botnet can still fill them: a key costs nothing to make, so no limit of the server's alone tells a junk request from a real one. It comes off when PO and Secondary agree that what's left is acceptable for a public list, or when something else closes it, such as an invitation or a proof of work.

End of the list.
