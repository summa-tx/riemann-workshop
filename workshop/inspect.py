from riemann import tx
from riemann import utils as rutils

from typing import List


# # One sample block included in the repo
# # You can get more from blockchain.info
# https://blockchain.info/rawblock/000000000000000000059d8621464f112eb538abb24f60771853aa890e61fa20?format=hex

with open('data/000000000000000000059d8621464f112eb538abb24f60771853aa890e61fa20') as file:  # noqa: E501
    block_bytes = bytes.fromhex(file.read())


def as_btc(sats: float) -> str:
    '''
    Format a number as an amount of BTC for display to user

    # WARNING: This is not best practices. Float math will drop sats.
               Use integers wherever math is important
    '''
    return f'{sats / 100_000_000:.8f} BTC'


# The first 80 bytes of a block is the header
header = block_bytes[:80]

# Then, the block specifies how many txns are in it
num_txns = tx.VarInt.from_bytes(block_bytes[80:])
num_txns_len = len(num_txns)

# The rest of the block is the txns in a blob
txn_bytes = block_bytes[80 + num_txns_len:]

offset = 0
txns: List[tx.Tx] = []

# Loop through the txn_bytes, parsing txns off the front
# Riemann parsers all silently handle extra bytes.
# Each time we call from_bytes it returns a tx from the front of the bytearray
for i in range(num_txns.number):
    try:
        txns.append(tx.Tx.from_bytes(txn_bytes[offset:]))
        offset += len(txns[-1])
    except ValueError:
        print()
        print(f'Errored after {len(txns)} txns')
        print('please file an issue')
        print(txn_bytes[offset:].hex())
        break

# list the total output value of each tx
vals_out: List[int] = [
    sum(rutils.le2i(tx_out.value) for tx_out in t.tx_outs)
    for t in txns
]
num_outputs = sum(len(t.tx_outs) for t in txns)

# Calculate and output some basic stats
print()
print(f'block produced {num_outputs} new TXOs')
print(f'total output value of block is {as_btc(sum(vals_out))}')
print(f'mean output value is {as_btc(sum(vals_out) / num_outputs)}')
print(f'average tx output value is {as_btc(sum(vals_out) / len(vals_out))}')
print()
