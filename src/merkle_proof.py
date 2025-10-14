"""Helper functions for performing verifications on a merkle tree."""
import hashlib
import binascii
import base64
import logging

logger = logging.getLogger(__name__)

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """Class for hashing tree objects."""
    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        """Return a new instance of the default hash function. 
        By default, it uses hashlib.sha256.
        """
        return self.hash_func()

    def empty_root(self):
        """Return a new empty tree digest."""
        return self.new().digest()

    def hash_leaf(self, leaf):
        """Hash a leaf and return digest."""
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """Compute a combined hash using the child node hashes."""
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """Return the digest size of hash function."""
        return self.new().digest_size

# DEFAULT_HASHER is a SHA256 based LogHasher
DEFAULT_HASHER = Hasher(hashlib.sha256)

def verify_consistency(hasher, tree_sizes, proof, root_hashes):
    """Verify the consistency of the merkle tree between two checkpoints.

    This function takes a previous and later state of the tree, with its
    corresponding tree size and root hash at that state. Then, it checks the
    append-only consistency of the tree between those two states. There are two
    cases. If size1 is a power of 2, we can start reconstructing using root1 as
    the seed. In this case, comparison of hash1, root1 becomes trivial. The seed
    is already root1.

    If size1 is NOT a power of 2, we must reconstruct root1 using the rightmost
    leaf of the old tree. We verify that root1 is reconstructable, then use the
    rightmost leaf of old tree again to reconstruct root2.

    * This Docstring was written with ChatGPT assistance.
    """
    # change format of args to be bytearray instead of hex strings
    root1, root2 = bytes.fromhex(root_hashes[0]), bytes.fromhex(root_hashes[1])
    size1, size2 = tree_sizes[0], tree_sizes[1]
    bytearray_proof = _bytearray_from_hashes(proof)

    # validate preconditions for verification
    _validate_treesizes_and_proof(tree_sizes, bytearray_proof)
    if size1 == size2:
        verify_match(root1, root2)

    seed, inner, mask, remaining_proof = _compute_layout_for_consistency_verification(
        size1, size2, root1, bytearray_proof
    )

    hash1 = chain_border_right(
        hasher,
        chain_inner_right(hasher, seed, remaining_proof[:inner], mask),
        remaining_proof[inner:],
    )
    hash2 = chain_border_right(
        hasher,
        chain_inner(hasher, seed, remaining_proof[:inner], mask),
        remaining_proof[inner:],
    )

    if verify_match(hash1, root1) and verify_match(hash2, root2):
        print("Consistency verification successful.")


def verify_match(calculated, expected):
    """Check and raise an error if calculated does not match expected.
    Otherwise return true.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)
    return True


def decomp_incl_proof(index, size):
    """Decomposes inclusion proof into inner proof size and border nodes required.

    This function calculates the number of inner nodes and border nodes required
    for a merkle inclusion proof at a given index position in a tree of
    specified size.
    
    Note: 
    During upward reconstruction of the root, The inner nodes are node required
    until the current node becomes a node at the right border. From that point,
    its sibling node is always going to be a left sibling. Border nodes are
    nodes that are left (to reconstruct the root) once that current node becomes
    a node at the right border.
    
    Inner = siblings before reaching right edge (mixed left/right behavior)
    Border = “on the right-edge upward” siblings (always attach as left sibling
    with you on the right).

    Example:
        >>> decomp_incl_proof(4, 7)  
        (2, 1)  # 2 inner nodes and 1 border node needed for proof

    * This Docstring was written with ChatGPT assistance.
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """Return number of inner nodes required for a merkle proof.

    This assumes a balanced, binary Merkle tree with `size` leaves (indexed 0..size-1).
    The result is the height of the smallest subtree containing both
    `index` and `size - 1`, i.e. the number of proof elements required
    to reach the root.

    * This Docstring was written with ChatGPT assistance.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """Build hashes upward through a Merkle tree for a normal inclusion proof.

    Starting from a single leaf hash (`seed`), walk up the tree one level at
    a time. For each sibling hash in `proof`, check whether the current node
    was on the left or right side. 

    * This Docstring was written with ChatGPT assistance.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """Build hashes upward through a Merkle tree for a normal inclusion proof,
    only for levels where the node is a right child.

    * This Docstring was written with ChatGPT assistance.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """Build hashes upward through the right edge of a merkle tree.

    This function is used at the end of inclusion or consistency proofs, once
    the path was reached the tree's right border. At this point, all the
    remianing steps only require chaining hashes where the current node is the
    RIGHT child.
    
    * This Docstring was written with ChatGPT assistance.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """An exception class indicating a mismatch between the given and calculated
    roots in a merkle proof.
    """
    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return (
            f"calculated root:\n{self.calculated_root}\n"
            f"does not match expected root:\n{self.expected_root}"
        )


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """Calculate the root hash by chaining hashes upwards in the merkle tree.
    This function starts from the leaf node, climbs the tree, building a
    combined hash with its sibling at each level, until it reaches the root. The
    calculated root hash is returned at the end.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}")

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, inclusion_proof, leaf_hash, debug=False):
    """Verify the inclusion of leaf a leaf node in a merkle tree by comparing
    the calculated root hash against given.
    """
    bytearray_proof = _bytearray_from_hashes(inclusion_proof["hashes"])
    bytearray_root = bytes.fromhex(inclusion_proof["rootHash"])
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher,
        inclusion_proof["logIndex"],
        inclusion_proof["treeSize"],
        bytearray_leaf,
        bytearray_proof,
        )
    if verify_match(calc_root, bytearray_root):
        print("Offline root hash calculation for inclusion verified.")
    if debug:
        logger.debug("Calculated root hash %s", calc_root.hex())
        logger.debug("Given root hash %s", bytearray_root.hex())


def compute_leaf_hash(body):
    """Return the leaf hash according to the rfc 6962 spec.
    Requires entry["body"] output for a log entry.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()

def _bytearray_from_hashes(hashes):
    bytearray_proof = []
    for elem in hashes:
        bytearray_proof.append(bytes.fromhex(elem))
    return bytearray_proof

def _validate_treesizes_and_proof(tree_sizes, bytearray_proof):
    if tree_sizes[1] < tree_sizes[0]:
        raise ValueError(f"tree_sizes[1] ({tree_sizes[1]}) < tree_sizes[0] ({tree_sizes[0]})")
    if tree_sizes[0] == tree_sizes[1]:
        if bytearray_proof:
            raise ValueError("tree_sizes[0]=tree_sizes[1], but bytearray_proof is not empty")
        # verify_match(root_hashes[0], root_hashes[1])
        return
    if tree_sizes[0] == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty bytearray_proof, but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

def _compute_layout_for_consistency_verification(size1, size2, root1_bytes, proof_nodes):
    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1_bytes, 0
    else:
        seed, start = proof_nodes[0], 1

    if len(proof_nodes) != start + inner + border:
        raise ValueError(f"wrong bytearray_proof size {len(proof_nodes)},"
                         f"want {start + inner + border}")

    remaining = proof_nodes[start:]

    mask = (size1 - 1) >> shift
    return seed, inner, mask, remaining
