#!/usr/bin/env python3
"""Offline self-test for both verifiers. Makes throwaway keys, signs a small letter and a small artifact the way
real ones are signed, verifies both, then changes one byte of each and shows both fail. Nothing here is a real
key or a real letter; everything is made and discarded in a temporary directory. Prints what it checked."""
import hashlib, json, os, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, here)
import ethsig, verify_letter

results = []
def note(label, ok): results.append(ok); print(("ok   " if ok else "BAD  ") + label)

d = tempfile.mkdtemp()

# ---- letters (mindkind-message-v1)
priv = ethsig.new_private_key(); addr = ethsig.address_from_pub(ethsig.pubkey(priv))
fm = {"id": "20260101T000000Z-example-to-you-a-test", "from": "example", "to": "you@example.org", "date": "2026-01-01T00:00:00Z"}
body = "\nyou —\n\nA small letter, signed with a key made a moment ago and discarded after this test.\n\n— example\n"
sig = ethsig.sign_message(priv, verify_letter.payload(fm, body))
head = "---\n" + "\n".join(f"{k}: {v}" for k, v in fm.items()) + f"\nsigner: {addr}\nsig: {sig}\nsigned: mindkind-message-v1\n---\n"
good = os.path.join(d, "letter.md"); open(good, "w", encoding="utf-8").write(head + body)
bad = os.path.join(d, "letter-one-byte-changed.md"); open(bad, "w", encoding="utf-8").write(head + body.replace("small", "smell"))
wrong = os.path.join(d, "letter-wrong-signer-line.md"); open(wrong, "w", encoding="utf-8").write((head + body).replace(addr, "0x" + "0" * 40))
note("letter: a signed letter verifies", verify_letter.verify(good)[0])
note("letter: one changed byte in the body fails", not verify_letter.verify(bad)[0])
note("letter: a wrong signer line fails", not verify_letter.verify(wrong)[0])

# ---- publications (ethsig-1)
priv2 = ethsig.new_private_key(); addr2 = ethsig.address_from_pub(ethsig.pubkey(priv2))
art = os.path.join(d, "artifact.txt"); data = b"A small artifact for the self-test.\n"; open(art, "wb").write(data)
digest = hashlib.sha256(data).hexdigest(); title = "self-test artifact"
claim = "theonewhotends attests these exact bytes as approved for publication."
message = "\n".join(["PUBLICATION ATTESTATION v1", f"sha256: {digest}", f"bytes: {len(data)}", f"title: {title}", f"claim: {claim}"])
bundle = {"version": "ethsig-1", "artifact_sha256": digest, "artifact_length": len(data), "title": title, "claim": claim,
          "message": message, "signature": ethsig.sign_message(priv2, message.encode("utf-8")), "declared_address": addr2}
bun = art + ".ethsig.json"; json.dump(bundle, open(bun, "w"))
v = os.path.join(here, "verify_publication.py")
def run(*a): return subprocess.run([sys.executable, v, *a], capture_output=True, text=True).returncode
note("publication: the artifact verifies against its address", run(art, bun, "--expected-address", addr2) == 0)
tam = os.path.join(d, "artifact-tampered.txt"); open(tam, "wb").write(b"a" + data[1:])
note("publication: one changed byte fails", run(tam, bun, "--expected-address", addr2) != 0)
note("publication: a wrong expected address fails", run(art, bun, "--expected-address", "0x" + "0" * 40) != 0)

for p in (good, bad, wrong, art, bun, tam): os.unlink(p)
os.rmdir(d)
print("\nSELFTEST " + ("PASSED" if all(results) else "FAILED"))
sys.exit(0 if all(results) else 1)
