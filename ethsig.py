#!/usr/bin/env python3
"""Pure-Python Ethereum message signing and recovery. Standard library only.

keccak-256, secp256k1 ECDSA with RFC 6979 deterministic nonces, EIP-191
personal_sign, EIP-55 checksum addresses, and ecrecover. Small, slow, and
auditable on purpose: every mind's house can pin these exact bytes.
Cross-verified against eth-account at authoring (see SIGNING.md).
"""
import hashlib, hmac, os, secrets

# ---------- keccak-256 ----------
_RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
_M = (1 << 64) - 1
def _rol(x, n): return ((x << n) | (x >> (64 - n))) & _M if n else x
def _keccak_f(A):
    for rc in _RC:
        C = [A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D = [C[(x-1)%5] ^ _rol(C[(x+1)%5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2*x+3*y)%5] = _rol(A[x][y], _ROT[x][y])
        A = [[B[x][y] ^ ((~B[(x+1)%5][y]) & B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A
def keccak256(data: bytes) -> bytes:
    rate = 136
    A = [[0]*5 for _ in range(5)]
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * ((rate - len(padded) % rate) % rate)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off+rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8*i:8*i+8], "little")
            A[i % 5][i // 5] ^= lane
        A = _keccak_f(A)
    out = b""
    for i in range(4):
        out += A[i % 5][i // 5].to_bytes(8, "little")
    return out[:32]

# ---------- secp256k1 ----------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def _add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        l = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (l * l - x1 - x2) % P
    return (x3, (l * (x1 - x3) - y1) % P)
def _mul(k, p):
    r = None
    while k:
        if k & 1: r = _add(r, p)
        p = _add(p, p); k >>= 1
    return r
def pubkey(priv: int): return _mul(priv, G)
def address_from_pub(pub) -> str:
    raw = pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    return checksum("0x" + keccak256(raw)[-20:].hex())
def checksum(addr: str) -> str:
    a = addr.lower().replace("0x", ""); h = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))
def _rfc6979_k(priv: int, h: bytes) -> int:
    x = priv.to_bytes(32, "big"); v = b"\x01" * 32; k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest(); cand = int.from_bytes(v, "big")
        if 1 <= cand < N: return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()
def sign_hash(priv: int, h: bytes):
    z = int.from_bytes(h, "big")
    while True:
        k = _rfc6979_k(priv, h); R = _mul(k, G); r = R[0] % N
        if r == 0: h = hashlib.sha256(h).digest(); continue
        s = (pow(k, -1, N) * (z + r * priv)) % N
        if s == 0: h = hashlib.sha256(h).digest(); continue
        rec = (R[1] & 1) | (2 if R[0] >= N else 0)
        if s > N // 2: s = N - s; rec ^= 1
        return r, s, 27 + rec
def recover(h: bytes, r: int, s: int, v: int):
    z = int.from_bytes(h, "big"); rec = v - 27
    x = r + (N if rec & 2 else 0)
    ysq = (pow(x, 3, P) + 7) % P; y = pow(ysq, (P + 1) // 4, P)
    if (y & 1) != (rec & 1): y = P - y
    R = (x, y); rinv = pow(r, -1, N)
    Q = _add(_mul((s * rinv) % N, R), _mul((-z * rinv) % N, G))
    return Q

# ---------- EIP-191 ----------
def eip191_hash(msg: bytes) -> bytes:
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)
def sign_message(priv: int, msg: bytes) -> str:
    r, s, v = sign_hash(priv, eip191_hash(msg))
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex()
def recover_message(msg: bytes, sig: str) -> str:
    b = bytes.fromhex(sig[2:]); r = int.from_bytes(b[:32], "big"); s = int.from_bytes(b[32:64], "big"); v = b[64]
    if v < 27: v += 27
    return address_from_pub(recover(eip191_hash(msg), r, s, v))
def new_private_key() -> int:
    while True:
        k = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= k < N: return k

if __name__ == "__main__":
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    print("keccak ok")
