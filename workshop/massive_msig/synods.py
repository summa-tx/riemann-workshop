from riemann import utils as rutils
from riemann.encoding import addresses as addr
from riemann.script import serialization as ser

from riemann_keys import hdkey

from typing import List
from workshop.massive_msg.eris_types import HexVoter, Synod, SynodDiff, Voter

FIRST_VOTER_BLOCK = \
    '{pubkey} OP_CHECKSIG OP_IF {weight} OP_ELSE OP_0 OP_ENDIF'

VOTER_BLOCK = \
    'OP_SWAP {pubkey} OP_CHECKSIG OP_IF {weight} OP_ADD OP_ENDIF'

END_BLOCK = \
    '{quorum_weight} OP_GREATERTHAN'

SYNOD_MEMBER_LIMIT = 77


def validate_voter(voter: Voter) -> bool:
    '''
    Validates a voter
    '''
    if voter['weight'] <= 0:
        return False  # nonsense
    try:
        hdkey.HDKey.from_pubkey(bytes.fromhex(voter['pubkey']))
        assert len(voter['pubkey']) == 66  # 33 bytes in hex
    except Exception:
        return False  # bad key
    return True


def validate_synod(synod: Synod) -> bool:
    '''
    Validates a synod
    Includes validating all voters
    '''
    if len(synod) > SYNOD_MEMBER_LIMIT:
        return False  # too many voters
    for voter in synod:
        if not validate_voter(voter):
            return False
    return True


def hex_encode_voter(v: Voter) -> HexVoter:
    '''
    Encodes the voter's weight in LE hex for script serialization
    '''
    return HexVoter(
        weight=rutils.i2le_script(v['weight']),
        pubkey=v['pubkey'])


def identify_synod_changes(old: Synod, proposed: Synod) -> SynodDiff:
    '''
    Given 2 synods, determine who left and who entered
    Args:
        old      (Synod): the previous synod
        proposed (Synod): the new synod
    Returns:
        tuple(Synod, Synod): the departed and admitted voters
    '''
    departed = tuple(v for v in old if v not in proposed)
    admitted = tuple(v for v in proposed if v not in old)
    return departed, admitted


def determine_total_synod_weight(synod: Synod) -> int:
    '''
    Determines the summed weight of a synod
    '''
    return sum(v['weight'] for v in synod)


def determine_quorum_weight(synod: Synod) -> int:
    '''
    Determines the quorum_weight of a synod (set to three fifths)
    '''
    return sum((v['weight'] for v in synod)) * 3 // 5


def determine_quorum_weight_hex(synod: Synod) -> str:  # pragma: nocover
    '''
    Determine the quorum weight in hex for script serialization
    '''
    return rutils.i2le_script(determine_quorum_weight(synod))


def build_eris_witness_script(synod: Synod) -> str:
    '''
    Builds a redeem script given a synod
    Does this by crawling the synod and formatting voters into script blocks
    '''
    if not validate_synod(synod):
        raise ValueError('Invalid Synod')
    quorum_weight = determine_quorum_weight_hex(synod)
    hex_synod = [hex_encode_voter(v) for v in synod]

    blocks: List[str] = [FIRST_VOTER_BLOCK.format(**hex_synod[0])]
    blocks.extend(VOTER_BLOCK.format(**s) for s in hex_synod[1:])
    blocks.append(END_BLOCK.format(quorum_weight=quorum_weight))

    return ' '.join(blocks)


def build_serialized_eris_witness_script(
        synod: Synod) -> bytes:  # pragma: nocover
    '''
    Builds a serialized eris script given a synod
    '''
    return ser.serialize(build_eris_witness_script(synod))


def build_synod_address(synod: Synod) -> str:  # pragma: nocover
    '''
    Determines the p2wsh address of a synod
    '''
    return addr.make_p2wsh_address(build_eris_witness_script(synod))


def estimate_synod_spend_weight(synod: Synod) -> int:
    '''
    Estimates the weight accrued spending a synod
    Each signer imposes bytes:
    42 for script, 33 for pubkey, 75 for signature,
    2 extra for length prefixes
    10 extra on the end for padding

    The input is 36 (outpoint) + 1 (empty scriptsig) + 4 (nsequence)
    Multiply by 4 because in the tx body

    Args:
        synod (Synod): the synod
    Returns:
        (int): the estimated weight of the spending witness
    '''
    witness_weight = (42 + 33 + 75 + 2) * len(synod) + 10
    input_weight = (36 + 1 + 4) * 4
    output_weight = 1 + 8 + 3 + 32  # assume 1 output per input
    return witness_weight + input_weight + output_weight
