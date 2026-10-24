"""RFC 6962-style Merkle tree over an append-only event log.

The security property that matters: given a signed tree head and an inclusion
proof, a verifier can confirm an event is in the log *without* being given the
whole log and without trusting the log's operator. Anything less is a log the
operator can rewrite silently.

Two details are easy to get wrong and are handled explicitly here:

* The leaf and interior prefixes are different (0x00 and 0x01). Without that
  domain separation, a leaf can be crafted to hash identically to an interior
  node - the second-preimage attack that made early certificate logs
  rebuildable by an attacker.
* The right subtree of an unbalanced node is the *largest power of two* below
  the number of leaves. Splitting anywhere else still produces a consistent
  tree, but not the one every other RFC 6962 implementation agrees on, so proofs
  would not verify against other tooling.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _sha(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly less than `n`."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


@dataclass(frozen=True)
class TreeHead:
    size: int
    root: str

    def as_dict(self) -> dict:
        return {"size": self.size, "root": self.root}


class MerkleTree:
    """Append-only tree. `add` returns the new tree head."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []

    def __len__(self) -> int:
        return len(self._leaves)

    def add(self, data: bytes) -> TreeHead:
        self._leaves.append(leaf_hash(data))
        return self.head()

    def head(self) -> TreeHead:
        return TreeHead(size=len(self._leaves), root=self._root_hex(0, len(self._leaves)))

    def _root_hex(self, start: int, end: int) -> str:
        return self._root(start, end).hex()

    def _root(self, start: int, end: int) -> bytes:
        count = end - start
        if count == 0:
            return _sha(b"")
        if count == 1:
            return self._leaves[start]
        split = _split(count)
        return node_hash(
            self._root(start, start + split),
            self._root(start + split, end),
        )

    def inclusion_proof(self, index: int) -> list[str]:
        """The sibling hashes from leaf `index` up to the root."""
        if not 0 <= index < len(self._leaves):
            raise IndexError(f"leaf {index} is outside a tree of {len(self._leaves)}")

        proof: list[bytes] = []
        _collect(self._leaves, index, proof)
        return [h.hex() for h in proof]


def _collect(leaves: list[bytes], index: int, proof: list[bytes]) -> None:
    """Recursive walk that appends the sibling at each level, bottom up."""
    count = len(leaves)
    if count <= 1:
        return

    split = _split(count)
    if index < split:
        _collect(leaves[:split], index, proof)
        proof.append(_root_of(leaves[split:]))
    else:
        _collect(leaves[split:], index - split, proof)
        proof.append(_root_of(leaves[:split]))


def _root_of(leaves: list[bytes]) -> bytes:
    if not leaves:
        return _sha(b"")
    if len(leaves) == 1:
        return leaves[0]
    split = _split(len(leaves))
    return node_hash(_root_of(leaves[:split]), _root_of(leaves[split:]))


def verify_inclusion(index: int, size: int, data: bytes, proof: list[str],
                     root_hex: str) -> bool:
    """Recompute the root from a leaf and its proof.

    This is the function a third party runs. It touches no state and trusts
    nothing except the root it was given.
    """
    if size <= 0 or not 0 <= index < size:
        return False

    node = leaf_hash(data)
    fn, sn = index, size - 1

    for sibling_hex in proof:
        try:
            sibling = bytes.fromhex(sibling_hex)
        except ValueError:
            return False
        if len(sibling) != 32:
            return False

        if fn % 2 == 1 or fn == sn:
            node = node_hash(sibling, node)
            if fn % 2 == 0:
                # Walking off the right edge of an unbalanced level.
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            node = node_hash(node, sibling)
        fn //= 2
        sn //= 2

    return node.hex() == root_hex
