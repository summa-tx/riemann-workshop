import os

# ecdsa is a tight pure python library maintained by Brian Warner
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize

from typing import cast


def fake_privkey() -> bytes:
    '''
    Generate a dummy private key.
    Useful for tests that need to be deterministic.

    # WARNING: Do not use this in production.
    '''
    return b'\x01' * 32


def new_privkey() -> bytes:
    '''
    Generate a new private key from os entropy

    Check out riemann-keys for a full BIP32/39/44 ~experience~
    https://github.com/summa-tx/riemann-keys

    Even better: use riemann-ledger to connect to a ledger hardware wallet
    https://github.com/summa-tx/riemann-ledger

    # WARNING: This is not best practices.
    '''
    return os.urandom(32)


def sign_digest(digest: bytes, privkey: bytes) -> bytes:
    '''
    Sign a digest with a private key

    Bitcoin signatures must be DER encoded, so we pass in an encoder. The
    encoder also 'canonizes' the s-value of the signature. Bitcoin enforces
    low-s ECDSA signatures.

    Args:
        digest: the 32-byte digest to sign
        privkey: the 32-byte key to sign with

    Returns:
        A DER-encoded signature
    '''
    if len(digest) != 32:
        raise ValueError(f'digest must be 32 bytes. Got {len(digest)}')
    if len(privkey) != 32:
        raise ValueError(f'privkey must be 32 bytes. Got {len(privkey)}')
    signing_key = SigningKey.from_string(privkey, SECP256k1)
    sig = signing_key.sign_digest_deterministic(
        digest=digest,
        sigencode=sigencode_der_canonize
    )
    return cast(bytes, sig)


def _compress_raw_pubkey(pubkey: bytes) -> bytes:
    '''
    Return the compressed key corresponding to a raw key
    '''
    if len(pubkey) != 64:
        raise ValueError(f'pubkey must be 64 bytes. Got {len(pubkey)}')
    parity = (pubkey[-1] & 1) + 2
    compressed = bytes([parity]) + pubkey[:32]
    return compressed


def priv_to_pub(privkey: bytes) -> bytes:
    '''
    Return the compressed public key corresponding to a private key.
    SegWit txns enforce the use of compressed pubkeys. In legacy txns, you
    may still use uncompressed keys.

    Args:
        privkey: a 32-byte private key
    Returns:
        A 33-byte compressed pubkey, suitable for use in Bitcoin txns
    '''
    if len(privkey) != 32:
        raise ValueError(f'privkey must be 32 bytes. Got {len(privkey)}')

    pubkey = SigningKey.from_string(privkey, SECP256k1).verifying_key
    return _compress_raw_pubkey(pubkey.to_string())


def pow_mod(x: int, y: int, z: int) -> int:
    '''
    (x ** y) % z
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
    Returns the raw pubkey (64 bytes) corresponding to a compressed pubkey
    '''
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    parity = pubkey[0] - 2
    x = int.from_bytes(pubkey[1:], 'big')
    a = (pow_mod(x, 3, p) + 7) % p
    y = pow_mod(a, (p + 1) // 4, p)
    if y % 2 != parity:
        y = -y % p
    return (x.to_bytes(32, 'big')) + (y.to_bytes(32, 'big'))
