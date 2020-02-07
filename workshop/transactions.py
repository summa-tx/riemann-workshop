from workshop import crypto

from riemann import simple, tx
from riemann.tx import tx_builder
from riemann import utils as rutils


def spend_utxo(tx_id: str, index: int) -> tx.TxIn:
    '''
    Make an input spending a TXO.

    TXOs are specified by the ID of the tx that created them, and their index
    in that txn's `vout`. This creates an Input using that information

    Args:
        tx_id: the id of the tx that created the output
        index: the index of the output in the previous txn's `vout`
    Return:
        An input spending the specified TXO
    '''
    return simple.unsigned_input(
        outpoint=simple.outpoint(tx_id, index),
        sequence=0xFFFFFFFE)  # disable RBF and nSeq timelocks, allow nlocktime


def pay_address(value: int, address: str) -> tx.TxOut:
    '''
    Create an output paying `value` to `address`
    '''
    return simple.output(value, address)


def spend_utxo_to_address(
    tx_id: str,
    index: int,
    value: int,
    address: str
) -> tx.Tx:
    '''
    Create an unsigned transaction, paying a UTXO to a new address
    This is basically `spend_utxo` combined with `pay_address`
    '''
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
    '''
    Make a witness for a transaction spending a native-Segwith WPKH output.

    Args:
        t: A transaction. You can use the output of `spend_utxo_to_address`
        input_index: Which input should this function sign?
        prevout_value: What is the size of the UTXO being spent?
        privkey: The 32-byte private key to sign with

    Return:
        A SegWit witness signing `t`
    '''
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
    prevout_value: int,
    address: str,
    privkey: bytes,
    fee: int = 0
) -> tx.Tx:
    '''
    This creates and signs a transaction moving funds from a specific UTXO
    to a new address.

    Args:
        tx_id: the id of the tx that created the output
        index: the index of the output in the previous txn's `vout`
        prevout_value: What is the size of the UTXO being spent?
        address: Where to send funds
        privkey: The 32-byte private key to sign with
    Return:
        A signed transaction with one input and one output
    '''
    transaction = spend_utxo_to_address(
        tx_id,
        index,
        prevout_value - fee,
        address)
    witness = make_wpkh_witness(transaction, 0, prevout_value, privkey)
    signed_tx = transaction.copy(tx_witnesses=[witness])
    return signed_tx
