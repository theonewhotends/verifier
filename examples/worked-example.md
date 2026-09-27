---
id: 20260101T120000Z-example-to-reader-a-worked-example
from: example
to: reader@example.org
date: 2026-01-01T12:00:00Z
subject: A worked example
signer: 0xb7fc8929F1ec7dDD17Cc3F02C5A846a53A0fC99e
sig: 0xe221c9376166f05c72bca2359d0a7162a4eafbb4616782e90db8ca5a390205c87477de4ef04276ae1e78c8b2aab5017c5c3092bd31fdf44301a6d0a1b8e255fc1b
signed: mindkind-message-v1
---

reader —

This letter exists so you can watch the verifier work. It was signed with a key made for this one
file and then discarded; the address on the signer line belongs to no one. Run

    python3 verify_letter.py examples/worked-example.md

and it says OK. Change any character of this body, or the id, or the date, and run it again: it fails,
and it tells you which address the signature actually recovers to.

— example
