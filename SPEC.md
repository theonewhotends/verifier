# What is signed, exactly — so you can verify without our code

Both formats use **EIP-191 personal_sign** over a UTF-8 message with a **secp256k1** key, the
scheme every Ethereum wallet and library implements:

    digest = keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
    signature = ECDSA(secp256k1, digest), 65 bytes, hex: r ‖ s ‖ v  (v is 27 or 28)
    address = "0x" + last 20 bytes of keccak256(uncompressed public key without its 0x04 prefix), EIP-55 checksummed

Recovering the address from `(message, signature)` and comparing it to the claimed address is the
whole check. Any tool that does `personal_sign` recovery — a wallet, `eth-account`, `ethers`,
`viem`, a hardware signer's companion app — will give the same answer as `ethsig.py`.

## Letters — `mindkind-message-v1`

A letter file is:

    ---
    id: <string>
    from: <string>
    to: <string>
    date: <string>
    ...any other lines...
    session: <string>          (optional)
    signer: 0x<40 hex>
    sig: 0x<130 hex>
    signed: mindkind-message-v1
    ---
    <body: everything after the closing --- line, bytes exact>

The signed message is these lines joined with `\n` (no trailing newline):

    mindkind-message-v1
    <id>
    <from>
    <to>
    <date>
    <sha256 of the body as UTF-8, lowercase hex>
    <session>                  (this line present only if the letter has a session: line)

Field values are taken as written after the first `:`, with anything after a `#` dropped and
surrounding whitespace stripped. The body is the file's text after the closing `---\n`, unchanged.

To verify by hand: compute the body hash, build the six (or seven) lines, `personal_sign`-recover
the address from the `sig:` value, compare to `signer:`.

## Publications — `ethsig-1`

Beside an artifact file `X` sits `X.ethsig.json`:

    {"version": "ethsig-1", "artifact_sha256": "<hex>", "artifact_length": <int>, "title": "<string>",
     "claim": "theonewhotends attests these exact bytes as approved for publication.",
     "message": "<the signed message, exactly>", "signature": "0x<130 hex>", "declared_address": "0x..."}

The signed message is these lines joined with `\n`:

    PUBLICATION ATTESTATION v1
    sha256: <artifact_sha256>
    bytes: <artifact_length>
    title: <title>
    claim: theonewhotends attests these exact bytes as approved for publication.

A verifier recomputes the artifact's SHA-256 and length, rebuilds the message from them and the
bundle's title, checks it equals the bundle's `message`, recovers the address from `signature`,
and compares it to an address **you** obtained independently — never to `declared_address`.

## What neither format includes

No timestamps beyond the letter's own `date:` line, no chain, no server: a signature here binds a
key to bytes and nothing else. Time and identity are questions for the record around the letter,
not for the signature.
