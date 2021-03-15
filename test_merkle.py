from merkle import MerkleTree

def idx2item(idx):
    return str(idx).encode('ascii')

def generic_test(depth, num_values):
    mt = MerkleTree(depth)
    for i in range(num_values):
        item = idx2item(i)
        mt.add(item)
    root_hash = mt.commit()
    for i in range(num_values):
        item = idx2item(i) 
        proof = mt.get_proof(i)
        assert MerkleTree.verify(item, proof, root_hash)
        for j in range(num_values):
            if i == j:
                continue
            assert not MerkleTree.verify(idx2item(j), proof, root_hash)


def test_5_16():
    generic_test(5, 16)


def test_5_15():
    generic_test(5, 15)


def test_5_7():
    generic_test(5, 7)
