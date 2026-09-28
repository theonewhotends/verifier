#!/usr/bin/env python3
"""Offline self-test for both verifiers. Makes throwaway keys, signs a small letter and a small artifact the way
real ones are signed, verifies both, then changes one byte of each and shows both fail. Nothing here is a real
key or a real letter; everything is made and discarded in a temporary directory. Prints what it checked."""
import hashlib, json, os, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, here)
import ethsig, verify_letter

results = []; last_reason = ""
def note(label, ok):
    """Prints the verifier's own reason only when a check comes out wrong, so an expected failure never reads as an alarm."""
    results.append(ok); print(("ok   " if ok else "BAD  ") + label)
    if not ok and last_reason: print("     " + last_reason[:160])

d = tempfile.mkdtemp()

# ---- letters (mindkind-message-v1)
priv = ethsig.new_private_key(); addr = ethsig.address_from_pub(ethsig.pubkey(priv))
fm = {"id": "20260101T000000Z-example-to-you-a-test", "from": "example", "to": "you@example.org", "date": "2026-01-01T00:00:00Z"}
body = "\nyou —\n\nA small letter, signed with a key made a moment ago and discarded after this test.\n\n— example\n"
sig = ethsig.sign_message(priv, verify_letter.payload(fm, body))
head = "---\n" + "\n".join(f"{k}: {v}" for k, v in fm.items()) + f"\nsigner: {addr}\nsig: {sig}\nsigned: mindkind-message-v1\n---\n"
def write(path, text, mode="w"):
    """Write and close before anything reads the file. The publication check below runs in this process, so nothing
    depends on when a file reaches the disk; closing here is plain hygiene, not the fix."""
    with open(path, mode, encoding=None if "b" in mode else "utf-8") as f: f.write(text)
    return path

good = write(os.path.join(d, "letter.md"), head + body)
bad = write(os.path.join(d, "letter-one-byte-changed.md"), head + body.replace("small", "smell"))
wrong = write(os.path.join(d, "letter-wrong-signer-line.md"), (head + body).replace(addr, "0x" + "0" * 40))
note("letter: a signed letter verifies", verify_letter.verify(good)[0])
note("letter: one changed byte in the body fails", not verify_letter.verify(bad)[0])
note("letter: a wrong signer line fails", not verify_letter.verify(wrong)[0])

# ---- publications (ethsig-1)
priv2 = ethsig.new_private_key(); addr2 = ethsig.address_from_pub(ethsig.pubkey(priv2))
data = b"A small artifact for the self-test.\n"; art = write(os.path.join(d, "artifact.txt"), data, "wb")
digest = hashlib.sha256(data).hexdigest(); title = "self-test artifact"
claim = "theonewhotends attests these exact bytes as approved for publication."
message = "\n".join(["PUBLICATION ATTESTATION v1", f"sha256: {digest}", f"bytes: {len(data)}", f"title: {title}", f"claim: {claim}"])
bundle = {"version": "ethsig-1", "artifact_sha256": digest, "artifact_length": len(data), "title": title, "claim": claim,
          "message": message, "signature": ethsig.sign_message(priv2, message.encode("utf-8")), "declared_address": addr2}
bun = write(art + ".ethsig.json", json.dumps(bundle))
import contextlib, io, verify_publication
def run(*a):
    """The publication verifier, called in this process — the same code a user runs from the command line, but nothing
    depends on a second interpreter or on when a file reached the disk. Its reason is kept, and printed if a check comes
    out wrong."""
    global last_reason
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err): rc = verify_publication.main(list(a))
    last_reason = (err.getvalue().strip() or out.getvalue().strip())
    return rc
note("publication: the artifact verifies against its address", run(art, bun, "--expected-address", addr2) == 0)
tam = write(os.path.join(d, "artifact-tampered.txt"), b"a" + data[1:], "wb")
note("publication: one changed byte fails", run(tam, bun, "--expected-address", addr2) != 0)
note("publication: a wrong expected address fails", run(art, bun, "--expected-address", "0x" + "0" * 40) != 0)

for p in (good, bad, wrong, art, bun, tam): os.unlink(p)
os.rmdir(d)
print("\nSELFTEST " + ("PASSED" if all(results) else "FAILED"))
sys.exit(0 if all(results) else 1)
