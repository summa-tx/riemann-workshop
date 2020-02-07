from riemann.tx import tx_builder
from riemann import simple, script
from riemann import utils as rutils
from riemann.encoding import addresses

from workshop import crypto
from workshop.transactions import spend_utxo

from riemann import tx

'''
This is a hash timelock contract. It locks BTC until a timeout, or until a
specific secret is revealed.

HTLCs are used in cross-chain swaps, and are the core primitive for updating
lightning channels. Because of this, they can also be used to build cool things
like submarine (lightning-to-mainnet) atomic swaps.

Basically, an HTLC has 2 paths: execute and refund. The execute path checks a
secret against a pre-committed digest, and validates the executor's signature.
The refund path checks a timeout, and validates the funder's signature.

This script must be parameterized with a 32 byte hash, a timeout, and both
parties' pubkeyhashes.

# WARNING: This is an example. Do not use it in production.
'''
htlc_script = \
    'OP_IF ' \
    'OP_SHA256 {secret_hash} OP_EQUALVERIFY ' \
    'OP_DUP OP_HASH160 {pkh0} ' \
    'OP_ELSE ' \
    '{timeout} OP_CHECKLOCKTIMEVERIFY OP_DROP ' \
    'OP_DUP OP_HASH160 {pkh1} ' \
    'OP_ENDIF ' \
    'OP_EQUALVERIFY ' \
    'OP_CHECKSIG'


def build_htlc_script(
    secret_hash: bytes,
    redeemer_pkh: bytes,
    timeout: int,
    funder_pkh: bytes
) -> str:
    '''
    Parameterizes the HTLC script with the arguments.
    '''
    if len(secret_hash) != 32:
        raise ValueError('Expected a 32-byte digest. '
                         f'Got {len(secret_hash)} bytes')
    if len(redeemer_pkh) != 20:
        raise ValueError('Expected a 20-byte redeemer pubkeyhash. '
                         f'Got {len(redeemer_pkh)} bytes')
    if len(funder_pkh) != 20:
        raise ValueError('Expected a 20-byte funder pubkeyhash. '
                         f'Got {len(redeemer_pkh)} bytes')
    return htlc_script.format(
        secret_hash=secret_hash.hex(),
        pkh0=rutils.sha256(redeemer_pkh).hex(),
        timeout=rutils.i2le(timeout),
        pkh1=rutils.sha256(funder_pkh).hex())


def htlc_address(
    secret_hash: bytes,
    redeemer_pkh: bytes,
    timeout: int,
    funder_pkh: bytes
) -> str:
    '''Parameterizes the script, and returns the corresponding address'''
    s = build_htlc_script(secret_hash, redeemer_pkh, timeout, funder_pkh)
    return addresses.make_p2wsh_address(s)


def p2htlc_output(
    value: int,
    secret_hash: bytes,
    redeemer_pkh: bytes,
    timeout: int,
    funder_pkh: bytes
) -> tx.TxOut:
    '''Parameterizes the script, and creates an output paying that address'''
    address = htlc_address(secret_hash, redeemer_pkh, timeout, funder_pkh)
    return simple.output(value, address)


def htlc_refund_witness(
    htlc_script: str,
    signature: bytes,
    pubkey: bytes
) -> tx.InputWitness:
    '''
    Given a signature, creates a witness for the refund path of the HTLC

    The b'\x00' corresponds to OP_FALSE
    '''
    serialized = script.serialize(htlc_script)
    return tx_builder.make_witness([signature, pubkey, b'\x00', serialized])


def htlc_execute_witness(
    htlc_script: str,
    signature: bytes,
    pubkey: bytes,
    secret: bytes
) -> tx.InputWitness:
    '''
    Given a signature and the secret, makes a witness for the execute path of
    the HTLC.

    The b'\x01' corresponds to OP_TRUE
    '''
    serialized = script.serialize(htlc_script)
    return tx_builder.make_witness(
        [signature, pubkey, secret, b'\x01', serialized]
    )


def spend_htlc_transaction(
    tx_id: str,
    index: int,
    value: int,
    address: str,
    timeout: int = 0
) -> tx.Tx:
    '''
    Creates an unsigned txn that sends funds from an HTLC to a specified
    address.

    Not that this step requires knowledge only of the timeout. An exercise tx
    can safely leave this at 0.
    '''
    tx_in = spend_utxo(tx_id, index)
    tx_out = simple.output(value, address)
    return simple.unsigned_witness_tx(  # type: ignore
        tx_ins=[tx_in],
        tx_outs=[tx_out],
        locktime=timeout)


def signed_refund_htlc_transaction(
    secret_hash: bytes,
    redeemer_pkh: bytes,
    timeout: int,
    funder_pkh: bytes,
    tx_id: str,
    index: int,
    prevout_value: int,
    address: str,
    privkey: bytes,
    fee: int = 0
) -> tx.Tx:
    '''
    Builds an entire Refund HTLC spend from scratch.
    '''
    # build the unsigned version of the transaction
    t = spend_htlc_transaction(
        tx_id,
        index,
        prevout_value - fee,
        address,
        timeout)

    # Prep the witness program
    s = build_htlc_script(secret_hash, redeemer_pkh, timeout, funder_pkh)
    serialized_script = script.serialize(s)
    script_len = len(serialized_script)
    prepended_script = tx.VarInt(script_len).to_bytes() + serialized_script

    # calculate sighash using the witness program
    sighash = t.sighash_all(
        index=index,
        script=prepended_script,
        prevout_value=rutils.i2le_padded(prevout_value, 8))

    # sign it and make the witness
    signature = crypto.sign_digest(sighash, privkey)
    witness = htlc_refund_witness(s, signature, crypto.priv_to_pub(privkey))

    # insert the witness into the tx
    return t.copy(tx_witnesses=[witness])
