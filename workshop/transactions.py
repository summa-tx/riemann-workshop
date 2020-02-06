from workshop import crypto

from riemann import simple, tx
from riemann.tx import tx_builder
from riemann import utils as rutils


def spend_utxo(tx_id: str, index: int) -> tx.TxIn:
    '''Make an input spending a UTXO'''
    return simple.unsigned_input(
        outpoint=simple.outpoint(tx_id, index),
        sequence=0xFFFFFFFE)  # disable RBF and nSeq timelocks, allow nlocktime


def pay_address(value: int, address: str) -> tx.TxOut:
    return simple.output(value, address)


def spend_utxo_to_address(
    tx_id: str,
    index: int,
    value: int,
    address: str
) -> tx.Tx:
    tx_in = spend_utxo(tx_id, index)
    tx_out = pay_address(value, address)
    transaction = simple.unsigned_witness_tx(tx_ins=[tx_in], tx_outs=[tx_out])
    return transaction  # type: ignore


def make_wpkh_witness(
    t: tx.Tx,
    input_index: int,
    prevout_value: int,
    privkey: bytes
) -> tx.InputWitness:
    pubkey = crypto.priv_to_pub(privkey)

    sighash = t.sighash_all(
        index=input_index,
        script=b'\x16\x00\x14' + rutils.hash160(pubkey),
        prevout_value=rutils.i2le_padded(prevout_value, 8))

    signature = crypto.sign_digest(sighash, privkey)

    return tx_builder.make_witness([signature, pubkey])


def move_utxo_to_address(
    tx_id: str,
    index: int,
    value: int,
    address: str,
    privkey: bytes,
    fee: int = 0
) -> tx.Tx:
    transaction = spend_utxo_to_address(tx_id, index, value - fee, address)
    witness = make_wpkh_witness(transaction, 0, value, privkey)
    signed_tx = transaction.copy(tx_witnesses=[witness])
    return signed_tx
