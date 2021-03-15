def _hash(b):
    import hashlib
    return hashlib.sha256(b).digest()

def _inner_hash(b):
    return _hash(b'\x01' + b)

def _leaf_hash(b):
    return _hash(b'\x00' + b)

def _nil_hash(b):
    return _hash(b'\x02' + b)

def _short_hash_str(h):
    return h.hex()[:6]

class _MerkleNode():
    def __init__(self, value, parent=None, left=None, right=None):
        self.value = value
        self.left = left
        self.right = right
        self.parent = parent

    def __str__(self):
        def str_depth(self, depth):
            s = ''
            if self.right is not None:
                s += str_depth(self.right, depth+1)
            s += '\t'*depth + _short_hash_str(self.value) + '\n'
            if self.left is not None:
                s += str_depth(self.left, depth+1)
            return s
        return str_depth(self, 0)

_DIRECTION_LEFT = 'L'
_DIRECTION_RIGHT = 'R'

_NIL = b'\x00'*32

class MerkleTree():
    """
    Fixed-depth Merkle tree implementation.

    Usage:
    ```
    >>> mt = MerkleTree(4)

    >>> idx0 = mt.add(b'0')
    >>> idx1 = mt.add(b'1')
    >>> idx2 = mt.add(b'2')
    >>> idx3 = mt.add(b'3')

    >>> root_hash = mt.commit()

    >>> proof = mt.get_proof(idx0)

    >>> assert MerkleTree.verify(b'0', proof, root_hash)
    ```
    """
    def __init__(self, depth):
        self.leaves = []
        self.depth = depth
        self.root = None
        self._n_leaves_committed = 0
        self._init_nil_hash()

    def add(self, item):
        """ Add leaf to the Merkle tree. """
        assert isinstance(item, bytes)
        leaf = _MerkleNode(_leaf_hash(item))
        self.leaves.append(leaf)
        return len(self.leaves)-1

    def get_proof(self, leaf_idx):
        """ Returns proof of membership for the leaf whose index is given. """
        assert len(self.leaves) == self._n_leaves_committed and self.root is not None
        assert 0 <= leaf_idx < self._n_leaves_committed

        curr_node = self.leaves[leaf_idx]
        proof = []
        d = self.depth - 1
        while d > 0:
            assert curr_node.parent is not None
            left_child = curr_node.parent.left
            right_child = curr_node.parent.right
            if right_child == curr_node:
                sibling = left_child
                direction = _DIRECTION_RIGHT
            else:
                sibling = right_child
                direction = _DIRECTION_LEFT

            proof.append((direction, sibling.value))
            curr_node = curr_node.parent
            d -= 1
        return proof

    @staticmethod
    def verify(item, proof, root_hash):
        """ Returns True iff `proof` is a proof of membership for `item` 
        of a Merkle tree whose root hash is `root_hash`. """
        assert isinstance(item, bytes)
        assert isinstance(root_hash, bytes)
        curr_hash = _leaf_hash(item)
        for direction, sibling_hash in proof:
            if direction == _DIRECTION_LEFT:
                curr_hash = _inner_hash(curr_hash + sibling_hash)
            else:
                curr_hash = _inner_hash(sibling_hash + curr_hash)
        return curr_hash == root_hash

    def commit(self):
        """ Commit to the leaves. Returns the root hash. """
        # build tree
        d = self.depth - 1
        curr_nodes = self.leaves
        while d > 0:
            i = 0
            new_nodes = []
            while i < len(curr_nodes):
                left = curr_nodes[i]
                if i + 1 < len(curr_nodes):
                    right = curr_nodes[i+1]
                else:
                    right = self._nil_node(d)
                
                # compute new node
                value = _inner_hash(left.value + right.value)
                new_node = _MerkleNode(value, left=left, right=right)

                # fixup parent pointers
                left.parent = new_node
                right.parent = new_node

                new_nodes.append(new_node)
                i += 2

            curr_nodes = new_nodes
            d -= 1
        assert len(curr_nodes) == 1
        self.root = curr_nodes[0]
        self._n_leaves_committed = len(self.leaves)
        return self.root.value

    def _nil_node(self, depth):
        return _MerkleNode(self.nil_hash[depth])

    def _init_nil_hash(self):
        self.nil_hash = [0]*self.depth
        curr_hash = _nil_hash(_NIL)
        d = self.depth - 1
        self.nil_hash[d] = curr_hash
        d -= 1
        while d >= 0:
            curr_hash = _inner_hash(curr_hash + curr_hash)
            self.nil_hash[d] = curr_hash
            d -= 1


def show_proof(proof):
    s = ''
    for direction, h in proof:
        s += direction + ':' + _short_hash_str(h) + ' => '
    s += '||\n'
    print(s)


