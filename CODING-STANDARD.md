# How we write code here

Written 2026-11-08 by Melanikus. **Every rule says why it exists and what enforces it.** A rule a machine checks names that check, and `tools/check-standard.js` runs every one of them on every change (GATES.md, "Coding standard"). A rule only a reviewer can check says so. When you add a rule, give it the next number, a plain reason, and its check, in the same change as the code that taught it.

## 1. Every file is ASCII
**Why:** a byte that looks like another, or one a tool reads two ways, can hide a change in plain sight. ASCII is the same in every editor and every tool, decades from now.
**Checked by:** check-standard.js, on every file git tracks. Write a character outside ASCII as a number (`String.fromCharCode(0xe9)`).

## 2. No third-party code
**Why:** every package is code we didn't write and can't keep an eye on (AVP Tao 1). Node's own modules do everything this server needs.
**Checked by:** check-standard.js:
- package.json has no dependencies of any kind;
- package-lock.json lists no package;
- no node_modules is tracked;
- every `require` names one of Node's own modules or a file of ours.

## 3. No code made from text
**Why:** `eval` and `Function` turn text into code. Text can come from the network, and then anyone could run anything.
**Checked by:** check-standard.js refuses `eval(`, `new Function(` and `Function(` everywhere.

## 4. The server starts no other program
**Why:** a program the server starts is a program an attacker could start through it. Only the tools that check the code (`tools/`) may.
**Checked by:** check-standard.js refuses `child_process` outside `tools/`.

## 5. The server writes nothing but through its log, and the log never holds an address
**Why:** the user's ruling: no IPs. One way out, `log()`, means one place to check. The tests check its lines hold no address, code, token or name.
**Checked by:** check-standard.js refuses `console.` in the server's own code (`relay/`, `list/`, `main.js`, `settings.js`, `log.js`). The tests (test/core.test.js) check what its lines hold.

## 6. A finding is fixed, never hidden
**Why:** a scanner told to look away is a scanner that isn't working (AVP Tao 1).
**Checked by:** check-standard.js refuses any comment or file that silences a scanner. The words it looks for are listed in check-standard.js itself.

## 7. Every action a workflow uses is pinned to a commit
**Why:** a tag can be moved to other code; a full commit hash can't.
**Checked by:** check-standard.js refuses a `uses:` in `.github/workflows/` that isn't a 40-digit hash or one of our own actions.

## 8. Every limit is a named number, written once
**Why:** a limit written in two places drifts apart, and a bare number says nothing about what it's for.
**Checked by:** a reviewer. PROTOCOL.md section 5 lists every limit, and the code names each one where it's set.

## 9. Comments in plain words
**Why:** someone decades from now, with nobody to ask, should be able to read why each part is the way it is (AVP Tao 2).
**Checked by:** a reviewer.
