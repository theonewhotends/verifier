#!/usr/bin/env python3
"""Verify a signed publication offline. No dependencies. Python 3.8+.

usage:
  python3 verify_publication.py <artifact> <artifact>.ethsig.json --expected-address 0x...

What it proves: that these exact artifact bytes were attested by the holder of
the key behind the address YOU supply. Anti-forgery only - not truth, not
authority, not identity beyond the key. The bundle's own declared_address is
ignored on purpose: get the expected address from an independent channel and
confirm it on two of them before trusting it.

Exit 0 = PASS (hash, length, and recovered signer all match). Anything else = FAIL.
Bundle format: ethsig-1 (identical to the reference Node verifier).
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ethsig

HEADER = "PUBLICATION ATTESTATION v1"
FIXED_CLAIM = "theonewhotends attests these exact bytes as approved for publication."
REQUIRED = ["version", "artifact_sha256", "artifact_length", "title", "claim", "message", "signature", "declared_address"]

def fail(reason):
    sys.stderr.write(f"FAIL: {reason}\n"); return 1

def main(argv):
    if len(argv) != 4 or argv[2] not in ("--expected-address", "--expected-address-file"):
        sys.stderr.write(__doc__); return 2
    artifact_path, bundle_path, opt, val = argv
    expected = open(os.path.expanduser(val)).read().strip() if opt == "--expected-address-file" else val
    if not (expected.startswith("0x") and len(expected) == 42): return fail("expected address malformed")
    try: artifact = open(artifact_path, "rb").read()
    except OSError: return fail("unable to read artifact")
    try: bundle = json.load(open(bundle_path, encoding="utf-8"))
    except (OSError, ValueError): return fail("unable to parse bundle")
    if not isinstance(bundle, dict) or set(bundle) != set(REQUIRED): return fail("bundle fields do not match ethsig-1")
    if bundle["version"] != "ethsig-1": return fail("bundle version is not ethsig-1")
    if bundle["claim"] != FIXED_CLAIM: return fail("bundle claim is not the fixed publication claim")
    digest = hashlib.sha256(artifact).hexdigest()
    if bundle["artifact_sha256"] != digest: return fail("artifact sha256 does not match bundle")
    if bundle["artifact_length"] != len(artifact): return fail("artifact length does not match bundle")
    expected_message = "\n".join([HEADER, f"sha256: {digest}", f"bytes: {len(artifact)}", f"title: {bundle['title']}", f"claim: {FIXED_CLAIM}"])
    if bundle["message"] != expected_message: return fail("bundle message does not match its own fields")
    sig = bundle["signature"]
    if not (isinstance(sig, str) and sig.startswith("0x") and len(sig) == 132): return fail("signature malformed")
    try: recovered = ethsig.recover_message(expected_message.encode("utf-8"), sig)
    except Exception: return fail("signature recovery failed")
    if recovered.lower() != expected.lower(): return fail(f"recovered signer {recovered} is not the expected address")
    print(f"PASS: {os.path.basename(artifact_path)} ({len(artifact)} bytes, sha256 {digest[:16]}...) attested by {recovered}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
