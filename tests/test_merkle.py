"""Merkle tree correctness: roots, proofs, and the attacks the design prevents."""

import hashlib

import pytest

from mcpaudit.merkle import (
    MerkleTree, leaf_hash, node_hash, verify_inclusion, _split,
)


class TestPrimitives:
    def test_leaf_and_node_prefixes_differ(self):
        data = b"same"
        assert leaf_hash(data) != node_hash(data, data)

    def test_leaf_hash_matches_the_documented_construction(self):
        assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()

    def test_node_hash_matches_the_documented_construction(self):
        left, right = b"a" * 32, b"b" * 32
        assert node_hash(left, right) == hashlib.sha256(b"\x01" + left + right).digest()


class TestSplit:
    @pytest.mark.parametrize("count,expected", [
        (2, 1), (3, 2), (4, 2), (5, 4), (7, 4), (8, 4), (9, 8), (16, 8),
    ])
    def test_split_is_the_largest_power_of_two_below_count(self, count, expected):
        assert _split(count) == expected


class TestRoots:
    def test_empty_tree_has_the_empty_root(self):
        assert MerkleTree().head().root == hashlib.sha256(b"").hexdigest()

    def test_a_single_leaf_root_is_its_leaf_hash(self):
        tree = MerkleTree()
        tree.add(b"only")
        assert tree.head().root == leaf_hash(b"only").hex()

    def test_two_leaves_hash_as_one_node(self):
        tree = MerkleTree()
        tree.add(b"a")
        tree.add(b"b")
        assert tree.head().root == node_hash(leaf_hash(b"a"), leaf_hash(b"b")).hex()

    def test_the_root_changes_when_a_leaf_changes(self):
        first, second = MerkleTree(), MerkleTree()
        for tree, payload in ((first, b"a"), (second, b"z")):
            tree.add(payload)
            tree.add(b"b")
        assert first.head().root != second.head().root

    def test_order_matters(self):
        a, b = MerkleTree(), MerkleTree()
        a.add(b"1"); a.add(b"2")
        b.add(b"2"); b.add(b"1")
        assert a.head().root != b.head().root

    def test_head_reports_the_size(self):
        tree = MerkleTree()
        for i in range(5):
            tree.add(str(i).encode())
        assert tree.head().size == 5


class TestProofs:
    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33])
    def test_every_leaf_proves_into_the_root(self, count):
        tree = MerkleTree()
        for i in range(count):
            tree.add(f"leaf-{i}".encode())
        head = tree.head()

        for i in range(count):
            proof = tree.inclusion_proof(i)
            assert verify_inclusion(i, count, f"leaf-{i}".encode(), proof, head.root), \
                f"leaf {i} of {count} failed to prove"

    def test_proof_length_is_logarithmic(self):
        tree = MerkleTree()
        for i in range(32):
            tree.add(str(i).encode())
        assert len(tree.inclusion_proof(0)) <= 6

    def test_a_wrong_leaf_fails(self):
        tree = MerkleTree()
        for i in range(4):
            tree.add(str(i).encode())
        proof = tree.inclusion_proof(1)
        assert not verify_inclusion(1, 4, b"not-the-leaf", proof, tree.head().root)

    def test_a_wrong_index_fails(self):
        tree = MerkleTree()
        for i in range(8):
            tree.add(str(i).encode())
        proof = tree.inclusion_proof(2)
        assert not verify_inclusion(3, 8, b"2", proof, tree.head().root)

    def test_a_wrong_root_fails(self):
        tree = MerkleTree()
        for i in range(4):
            tree.add(str(i).encode())
        assert not verify_inclusion(0, 4, b"0", tree.inclusion_proof(0), "00" * 32)

    def test_a_forged_proof_entry_fails(self):
        tree = MerkleTree()
        for i in range(4):
            tree.add(str(i).encode())
        proof = tree.inclusion_proof(0)
        proof[-1] = "ff" * 32
        assert not verify_inclusion(0, 4, b"0", proof, tree.head().root)

    def test_a_truncated_proof_fails(self):
        tree = MerkleTree()
        for i in range(4):
            tree.add(str(i).encode())
        proof = tree.inclusion_proof(0)[:-1]
        assert not verify_inclusion(0, 4, b"0", proof, tree.head().root)

    def test_a_non_hex_proof_entry_is_rejected(self):
        tree = MerkleTree()
        tree.add(b"a"); tree.add(b"b")
        proof = ["zz" * 32]
        assert not verify_inclusion(0, 2, b"a", proof, tree.head().root)

    def test_a_wrong_length_proof_entry_is_rejected(self):
        tree = MerkleTree()
        tree.add(b"a"); tree.add(b"b")
        assert not verify_inclusion(0, 2, b"a", ["00" * 16], tree.head().root)

    def test_an_out_of_range_index_is_refused(self):
        tree = MerkleTree()
        tree.add(b"a")
        assert not verify_inclusion(5, 1, b"a", tree.inclusion_proof(0), tree.head().root)
        assert not verify_inclusion(-1, 1, b"a", [], tree.head().root)

    def test_proving_a_missing_leaf_raises(self):
        tree = MerkleTree()
        tree.add(b"a")
        with pytest.raises(IndexError):
            tree.inclusion_proof(3)


class TestDomainSeparation:
    def test_a_crafted_leaf_cannot_collide_with_an_interior_node(self):
        """The attack the 0x00/0x01 prefixes exist to prevent.

        A tree of one leaf whose *content* is `left||right` must not produce the
        same root as a tree of those two leaves as separate entries.
        """
        left, right = leaf_hash(b"a"), leaf_hash(b"b")
        forged = MerkleTree()
        forged.add(left + right)

        genuine = MerkleTree()
        genuine.add(b"a")
        genuine.add(b"b")

        assert forged.head().root != genuine.head().root
