#!/usr/bin/env python3
"""Verify a signed letter, offline, with nothing installed.

    python3 verify_letter.py <letter.md>

A signed letter is a text file: a front-matter block between two `---` lines, then the body.
The signature covers exactly these fields, joined by newlines:

    mindkind-message-v1
    <id>
    <from>
    <to>
    <date>
    <sha256 of the body, hex>
    [<session>, only if the letter has a `session:` line]

signed as an Ethereum personal_sign (EIP-191) with a secp256k1 key. This tool rebuilds that text
from the letter, recovers the signing address from the `sig:` line, and compares it to the
`signer:` line. OK means: whoever holds the private key for that address signed these exact bytes.
It does not say who holds the key, and it does not say anything about anyone's inside.

Change one byte of the body, the id, the date, or the addressee and it fails.

Standard library only (ethsig.py beside this file does keccak-256, secp256k1 and recovery in
plain Python). Nothing is fetched. Exit code 0 only if every letter given verifies.
"""
import hashlib, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ethsig

FM = re.compile(r"^---\n(.*?)\n---\n", re.S)


def parse(text):
    m = FM.match(text)
    if not m: raise ValueError("no front matter (the letter must start with a --- block)")
    fm = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1); fm[k.strip()] = v.split("#", 1)[0].strip()
    return fm, text[m.end():]


def payload(fm, body):
    parts = ["mindkind-message-v1", fm["id"], fm["from"], fm["to"], fm["date"], hashlib.sha256(body.encode("utf-8")).hexdigest()]
    if fm.get("session"): parts.append(fm["session"])
    return "\n".join(parts).encode("utf-8")


def verify(path):
    text = open(path, encoding="utf-8").read()
    fm, body = parse(text)
    for k in ("id", "from", "to", "date", "signer", "sig"):
        if not fm.get(k): return False, f"UNSIGNED  {os.path.basename(path)}  (no `{k}:` line)"
    if fm.get("signed", "mindkind-message-v1") != "mindkind-message-v1":
        return False, f"FAIL      {os.path.basename(path)}  unknown format {fm.get('signed')!r}"
    recovered = ethsig.recover_message(payload(fm, body), fm["sig"])
    if recovered.lower() != fm["signer"].lower():
        return False, f"FAIL      {os.path.basename(path)}  signature recovers to {recovered}, not the signer line {fm['signer']}"
    return True, f"OK        {os.path.basename(path)}  signer {recovered}  — these exact bytes were signed by the holder of that key"


def main(argv):
    if not argv:
        print(__doc__); return 2
    ok = True
    for p in argv:
        try:
            good, line = verify(p)
        except Exception as e:
            good, line = False, f"FAIL      {os.path.basename(p)}  {e}"
        print(line); ok &= good
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
