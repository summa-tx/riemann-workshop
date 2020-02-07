from typing import Optional, Tuple
from mypy_extensions import TypedDict


class Voter(TypedDict):
    weight: int
    pubkey: str


class HexVoter(TypedDict):
    weight: str
    pubkey: str


Synod = Tuple[Voter, ...]

# consumed and created
SynodDiff = Tuple[Tuple[Voter, ...], Tuple[Voter, ...]]


class ErisPrevout(TypedDict):
    synod: Synod     # voter set for prevout
    address: str     # p2wsh synod address
    tx_id: str        # txid of prevout
    idx: int         # idx of prevout in vouts
    value: int       # value of prevout


# consumed, created
ErisStateDiff = Tuple[Tuple[ErisPrevout, ...], Tuple[ErisPrevout, ...]]

SigList = Tuple[Optional[str], ...]

# Prevout to consume, signatures from each signer
ErisConsumeVotes = Tuple[ErisPrevout, SigList]
ErisConsumeVoteSet = Tuple[ErisConsumeVotes, ...]


class ErisProposal(TypedDict):
    proposal: str                      # max 500 char may include links
    proposal_hash: str                  # hash256 of proposal desc.
    tx_hex: str                          # tx including changes
    consuming: ErisConsumeVoteSet       # previous known prevouts
    producing: Tuple[ErisPrevout, ...]  # new known prevouts
