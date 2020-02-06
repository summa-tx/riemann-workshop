from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize


def sign_digest(digest: bytes, privkey: bytes) -> bytes:
    signing_key = SigningKey.from_string(privkey, SECP256k1)
    sig = signing_key.sign_digest_deterministic(
        digest=digest,
        sigencode=sigencode_der_canonize
    )
    return sig



def priv_to_pub(privkey: bytes) -> bytes:
    pubkey = SigningKey.from_string(privkey, SECP256k1).verifying_key
    return compress_pubkey(pubkey.to_string())



def compress_pubkey(pubkey: bytes) -> bytes:
    parity = (pubkey[-1] & 1) + 2
    compressed = bytes([parity]) + pubkey[:32]
    return compressed


def pow_mod(x: int, y: int, z: int) -> int:
    '''
    int, int, int (or float)
    returns (x^y)mod z
    '''
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number


def uncompress_pubkey(pubkey: bytes) -> bytes:
    '''
    takes a compressed pubkey, returns the uncompressed pubkey (64 bytes)
    '''
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    parity = pubkey[0] - 2
    x = int.from_bytes(pubkey[1:], 'big')
    a = (pow_mod(x, 3, p) + 7) % p
    y = pow_mod(a, (p + 1) // 4, p)
    if y % 2 != parity:
        y = -y % p
    return (x.to_bytes(32, 'big')) + (y.to_bytes(32, 'big'))
