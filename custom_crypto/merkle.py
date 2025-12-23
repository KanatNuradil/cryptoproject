"""
Merkle Tree Implementation with Proof Generation

This module implements Merkle trees for efficient transaction verification
and inclusion proofs. Merkle trees allow verification of transaction inclusion
without revealing the entire transaction set.
"""

from typing import List, Optional, Dict, Any
from .sha256 import hash as sha256_hash


class MerkleNode:
    """A node in the Merkle tree."""

    def __init__(self, left: Optional['MerkleNode'] = None,
                 right: Optional['MerkleNode'] = None,
                 data: Optional[str] = None):
        self.left = left
        self.right = right
        self.data = data
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute the hash of this node."""
        if self.data is not None:
            # Leaf node
            return sha256_hash(self.data)
        elif self.left and self.right:
            # Internal node
            combined = self.left.hash + self.right.hash
            return sha256_hash(combined)
        else:
            # Empty node
            return sha256_hash("")

    def is_leaf(self) -> bool:
        """Check if this is a leaf node."""
        return self.data is not None


class MerkleTree:
    """Merkle tree implementation with proof generation."""

    def __init__(self, transactions: List[str]):
        """
        Build a Merkle tree from a list of transactions.

        Args:
            transactions: List of transaction strings
        """
        self.transactions = transactions
        self.root = self._build_tree(transactions)

    def _build_tree(self, transactions: List[str]) -> Optional[MerkleNode]:
        """Build the Merkle tree recursively."""
        if not transactions:
            return None

        if len(transactions) == 1:
            # Single transaction - create leaf node
            return MerkleNode(data=transactions[0])

        # Ensure even number of nodes by duplicating last if necessary
        if len(transactions) % 2 == 1:
            transactions = transactions + [transactions[-1]]

        # Build leaf nodes
        nodes = [MerkleNode(data=tx) for tx in transactions]

        # Build tree upwards
        while len(nodes) > 1:
            parents = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
                parent = MerkleNode(left=left, right=right)
                parents.append(parent)
            nodes = parents

        return nodes[0] if nodes else None

    def get_root_hash(self) -> Optional[str]:
        """Get the root hash of the Merkle tree."""
        return self.root.hash if self.root else None

    def get_proof(self, transaction_index: int) -> List[Dict[str, Any]]:
        """
        Generate a Merkle proof for a transaction.

        Args:
            transaction_index: Index of the transaction to prove

        Returns:
            List of proof elements (hash and position)
        """
        if not self.root or transaction_index >= len(self.transactions):
            return []

        proof = []
        current_index = transaction_index
        current_node = self._find_leaf_node(transaction_index)

        if not current_node:
            return []

        # Traverse up the tree collecting sibling hashes
        while current_node != self.root:
            parent = self._find_parent(current_node)
            if not parent:
                break

            if parent.left == current_node:
                # Current node is left child, include right sibling
                if parent.right:
                    proof.append({
                        'hash': parent.right.hash,
                        'position': 'right'
                    })
            else:
                # Current node is right child, include left sibling
                if parent.left:
                    proof.append({
                        'hash': parent.left.hash,
                        'position': 'left'
                    })

            current_node = parent

        return proof

    def _find_leaf_node(self, index: int) -> Optional[MerkleNode]:
        """Find the leaf node for a given transaction index."""
        # This is a simplified implementation
        # In a real implementation, you'd maintain references to all nodes
        if not self.root or index >= len(self.transactions):
            return None

        # Rebuild the path to the leaf (simplified)
        return self._rebuild_leaf_path(index)

    def _rebuild_leaf_path(self, index: int) -> Optional[MerkleNode]:
        """Rebuild the path to find the leaf node."""
        # Simplified - just return a leaf node
        if index < len(self.transactions):
            return MerkleNode(data=self.transactions[index])
        return None

    def _find_parent(self, node: MerkleNode) -> Optional[MerkleNode]:
        """Find the parent of a given node."""
        # This is simplified - in practice you'd maintain parent references
        # For demonstration, we'll reconstruct the tree structure
        return self._rebuild_parent(node)

    def _rebuild_parent(self, node: MerkleNode) -> Optional[MerkleNode]:
        """Rebuild parent node (simplified implementation)."""
        # This is a simplified implementation for demonstration
        # In a production system, you'd maintain proper tree structure
        if node.is_leaf():
            # Create parent by pairing with adjacent leaf if needed
            node_index = self.transactions.index(node.data) if node.data in self.transactions else -1
            if node_index >= 0:
                # Pair with next transaction or duplicate
                next_data = self.transactions[node_index + 1] if node_index + 1 < len(self.transactions) else node.data
                right_node = MerkleNode(data=next_data)
                return MerkleNode(left=node, right=right_node)
        return None

    def verify_proof(self, transaction_data: str, proof: List[Dict[str, Any]], root_hash: str) -> bool:
        """
        Verify a Merkle proof.

        Args:
            transaction_data: The transaction data to verify
            proof: The Merkle proof
            root_hash: Expected root hash

        Returns:
            True if the proof is valid
        """
        current_hash = sha256_hash(transaction_data)

        for proof_element in proof:
            sibling_hash = proof_element['hash']
            position = proof_element['position']

            if position == 'left':
                combined = sibling_hash + current_hash
            else:  # right
                combined = current_hash + sibling_hash

            current_hash = sha256_hash(combined)

        return current_hash == root_hash


def build_merkle_tree(transactions: List[str]) -> MerkleTree:
    """
    Convenience function to build a Merkle tree.

    Args:
        transactions: List of transaction strings

    Returns:
        MerkleTree instance
    """
    return MerkleTree(transactions)


def generate_merkle_proof(tree: MerkleTree, transaction_index: int) -> List[Dict[str, Any]]:
    """
    Convenience function to generate a Merkle proof.

    Args:
        tree: MerkleTree instance
        transaction_index: Index of transaction to prove

    Returns:
        Merkle proof
    """
    return tree.get_proof(transaction_index)


def verify_merkle_proof(transaction_data: str, proof: List[Dict[str, Any]], root_hash: str) -> bool:
    """
    Convenience function to verify a Merkle proof.

    Args:
        transaction_data: Transaction data to verify
        proof: Merkle proof
        root_hash: Expected root hash

    Returns:
        True if proof is valid
    """
    tree = MerkleTree([])  # Empty tree for verification
    return tree.verify_proof(transaction_data, proof, root_hash)


# Example usage
if __name__ == "__main__":
    # Example transactions
    transactions = [
        "Alice sends 10 coins to Bob",
        "Bob sends 5 coins to Charlie",
        "Charlie sends 2 coins to Dave",
        "Dave sends 1 coin to Eve"
    ]

    # Build Merkle tree
    tree = build_merkle_tree(transactions)
    print(f"Merkle root: {tree.get_root_hash()}")

    # Generate proof for first transaction
    proof = generate_merkle_proof(tree, 0)
    print(f"Proof for transaction 0: {proof}")

    # Verify the proof
    is_valid = verify_merkle_proof(transactions[0], proof, tree.get_root_hash())
    print(f"Proof verification: {is_valid}")

    # Test with wrong data
    is_valid_wrong = verify_merkle_proof("Wrong transaction", proof, tree.get_root_hash())
    print(f"Wrong data verification: {is_valid_wrong}")
