from riemann import tx
from riemann import utils as rutils

from typing import List

with open('data/000000000000000000059d8621464f112eb538abb24f60771853aa890e61fa20') as file:  # noqa: E501
    block_bytes = bytes.fromhex(file.read())


def as_btc(sats: float) -> str:
    return f'{sats / 100_000_000:.8f} BTC'


header = block_bytes[:80]

# a serialized block specifies how many txns are in it
num_txns = tx.VarInt.from_bytes(block_bytes[80:])
num_txns_len = len(num_txns)

txn_bytes = block_bytes[80 + num_txns_len:]

offset = 0
txns: List[tx.Tx] = []

for i in range(num_txns.number):
    try:
        txns.append(tx.Tx.from_bytes(txn_bytes[offset:]))
        offset += len(transaction)
    except ValueError:
        print()
        print(f'Errored after {len(txns)} txns')
        print('please file an issue')
        print(txn_bytes[offset:].hex())
        break


vals_out: List[int] = [sum(rutils.le2i(tx_out.value) for tx_out in t.tx_outs) for t in txns]  # noqa: E501
num_outputs = sum(len(t.tx_outs) for t in txns)

print()
print(f'block produced {num_outputs} new TXOs')
print(f'total output value of block is {as_btc(sum(vals_out))}')
print(f'mean output value is {as_btc(sum(vals_out) / num_outputs)}')
print(f'average tx output value is {as_btc(sum(vals_out) / len(vals_out))}')
print()
