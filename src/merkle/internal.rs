use std::collections::VecDeque;

use blake3::{Hash, Hasher};

fn hash_two_hashes(h1: &Hash, h2: &Hash) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(h1.as_bytes());
    hasher.update(h2.as_bytes());
    hasher.finalize()
}

/// A binary Merkle tree, forming a commitment scheme to an underlying
/// sequence of binary strings.
///
/// The bottom level is the length of the input sequence of binary strings.
/// The top level is the second-to-tallest level in the tree, with the root
/// being contained within the [`Tree`] directly.
#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct Tree {
    root: Hash,
    levels: VecDeque<Vec<Hash>>,
}

/// A commitment to a binary Merkle tree.
#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct Commitment {
    pub(crate) root: Hash,
    pub(crate) num_items: u64,
}

impl Commitment {
    pub(crate) fn verify(&self, pf: &Proof) -> bool {
        let mut current_hash = blake3::hash(&pf.item);
        let mut current_index = pf.index;
        let mut width = self.num_items;
        for i in 0..(pf.frontier.len() as u64) {
            let odd = width % 2;
            match &pf.frontier[i as usize] {
                ProofNode::NodeWithoutSibling => {
                    if current_index != width && odd != 1 {
                        return false;
                    }
                    current_index = current_index / 2;
                }
                ProofNode::LeftChildWithSibling(right_sibling_hash) => {
                    if current_index % 2 != 0 {
                        return false;
                    }

                    current_hash = hash_two_hashes(&current_hash, right_sibling_hash);
                    current_index = current_index / 2;
                }
                ProofNode::RightChildWithSibling(left_sibling_hash) => {
                    if current_index % 2 != 1 {
                        return false;
                    }

                    current_hash = hash_two_hashes(left_sibling_hash, &current_hash);
                    current_index = (current_index - 1) / 2;
                }
            }
            width = width / 2 + odd;
        }

        current_hash == self.root
    }
}

/// A proof of a particular element in the sequence committed to.
///
/// If our tree looks like:
///
/// ```text
/// R
/// |\
/// | \
/// |  \
/// |   \
/// A    B
/// |\   |\
/// | \  | \
/// 1  2 3 4
/// ```
///
/// and we want to prove knowledge of 1 relative to root R, then we
/// can show B, 1, 2 and the consumer of this proof can re-construct
/// A from 1 and 2. We reveal ancillary commitments to other data,
/// such as 2 and B, but those commitments are zero-knowledge unless
/// you can find collisions for the [`blake3::hash`] function.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Proof {
    item: Vec<u8>,
    index: u64,
    frontier: Vec<ProofNode>,
}

#[derive(Debug)]
pub enum ProofDecodingError {
    NotEnoughInput(usize),
    InvalidProofNodeType(u8),
}

impl TryFrom<&[u8]> for Proof {
    type Error = ProofDecodingError;

    fn try_from(encoded: &[u8]) -> Result<Self, Self::Error> {
        if encoded.len() < 8 {
            return Err(ProofDecodingError::NotEnoughInput(encoded.len()));
        }

        let mut i = 0;
        let next_byte = |i: &mut usize| {
            if let Some(&b) = encoded.get(*i) {
                *i += 1;
                Ok(b)
            } else {
                Err(ProofDecodingError::NotEnoughInput(encoded.len()))
            }
        };

        let next_u64 = |mut i: &mut usize| {
            let mut u64_bytes = [0u8; 8];
            for j in 0..8 {
                u64_bytes[j] = next_byte(&mut i)?;
            }
            Ok(u64::from_be_bytes(u64_bytes))
        };

        let next_n_bytes = |mut i: &mut usize, n: u64| {
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(next_byte(&mut i)?);
            }
            Ok(v)
        };

        let next_hash = |mut i: &mut usize| {
            let mut hash_bytes = [0u8; 32];
            for j in 0..32 {
                hash_bytes[j] = next_byte(&mut i)?;
            }
            Ok(Hash::from(hash_bytes))
        };

        let next_frontier_node = |mut i: &mut usize| {
            let tag = next_byte(&mut i)?;
            match tag {
                0 => Ok(ProofNode::NodeWithoutSibling),
                1 => Ok(ProofNode::LeftChildWithSibling(next_hash(&mut i)?)),
                2 => Ok(ProofNode::RightChildWithSibling(next_hash(&mut i)?)),
                b => Err(ProofDecodingError::InvalidProofNodeType(b)),
            }
        };

        let length = next_u64(&mut i)?;
        let item: Vec<u8> = next_n_bytes(&mut i, length)?;

        let index = next_u64(&mut i)?;
        let length = next_u64(&mut i)?;

        let mut frontier: Vec<ProofNode> = Vec::new();
        for _ in 0..length {
            frontier.push(next_frontier_node(&mut i)?);
        }

        Ok(Proof {
            item,
            index,
            frontier,
        })
    }
}

impl From<&Proof> for Vec<u8> {
    fn from(pf: &Proof) -> Self {
        fn encode_proof_node(pf_node: &ProofNode, output: &mut Vec<u8>) {
            match pf_node {
                ProofNode::NodeWithoutSibling => {
                    output.push(0);
                }
                ProofNode::LeftChildWithSibling(hash) => {
                    let bytes: [u8; 32] = hash.clone().into();
                    output.push(1);
                    for i in 0..32 {
                        output.push(bytes[i]);
                    }
                }
                ProofNode::RightChildWithSibling(hash) => {
                    let bytes: [u8; 32] = hash.clone().into();
                    output.push(2);
                    for i in 0..32 {
                        output.push(bytes[i]);
                    }
                }
            }
        }

        let mut output = Vec::new();
        output.extend((pf.item.len() as u64).to_be_bytes().iter().copied());
        output.extend(pf.item.iter().copied());
        output.extend((pf.index as u64).to_be_bytes().iter().copied());
        output.extend((pf.frontier.len() as u64).to_be_bytes().iter().copied());

        for node in pf.frontier.iter() {
            encode_proof_node(node, &mut output);
        }

        output
    }
}

#[derive(PartialEq, Eq, Debug)]
enum ProofNode {
    NodeWithoutSibling,
    LeftChildWithSibling(Hash),
    RightChildWithSibling(Hash),
}

/// A proof from a binary Merkle tree, representing evidence that a
/// particular index contains a particular element.

impl Tree {
    pub(crate) fn prove(&self, item: Vec<u8>, index: u64) -> Option<Proof> {
        let mut depth = self.levels.len();
        if depth == 0 {
            if index != 0 {
                return None;
            }
            if self.root == blake3::hash(&item) {
                return Some(Proof {
                    item,
                    index,
                    frontier: Vec::new(),
                });
            }
        }
        if let Some(hash) = self.levels[depth - 1].get(index as usize) {
            // reject the proof if the hash at the leaf is incorrect
            if *hash != blake3::hash(&item) {
                return None;
            }
        } else {
            // reject the proof if that index is absent
            return None;
        }

        let mut frontier: Vec<ProofNode> = Vec::new();
        let mut width = self.num_items();
        let mut current_index = index;
        loop {
            let odd = width % 2;
            if current_index == width && odd == 1 {
                frontier.push(ProofNode::NodeWithoutSibling);
                current_index = width / 2;
            } else if current_index % 2 == 0 {
                frontier.push(ProofNode::LeftChildWithSibling(
                    self.levels[depth - 1][(current_index + 1) as usize],
                ));
                current_index = current_index / 2;
            } else if current_index % 2 == 1 {
                frontier.push(ProofNode::RightChildWithSibling(
                    self.levels[depth - 1][(current_index - 1) as usize],
                ));
                current_index = (current_index - 1) / 2;
            }
            depth -= 1;
            if depth == 0 {
                break;
            }
            width = width / 2 + odd;
        }

        Some(Proof {
            item,
            index,
            frontier,
        })
    }

    pub(crate) fn num_items(&self) -> u64 {
        if self.levels.len() == 0 {
            return 1;
        } else {
            self.levels[self.levels.len() - 1].len() as u64
        }
    }

    pub(crate) fn new<'a>(leaves: &mut impl Iterator<Item = &'a [u8]>) -> Self {
        let mut levels: VecDeque<Vec<Hash>> = VecDeque::new();
        levels.push_front(leaves.map(blake3::hash).collect());
        if levels[0].len() == 1 {
            return Tree {
                root: levels[0][0],
                levels: VecDeque::new(),
            };
        }

        loop {
            let n = levels[0].len();
            if n == 2 {
                let root = hash_two_hashes(&levels[0][0], &levels[0][1]);

                return Tree { root, levels };
            } else {
                let odd = if n % 2 == 0 { 0 } else { 1 };
                let m = n - odd;
                let mut level: Vec<Hash> = vec![Hash::from([0u8; 32]); m / 2 + odd];
                let mut i = 0;
                loop {
                    if i == m / 2 {
                        break;
                    }

                    level[i] = hash_two_hashes(&levels[0][i * 2], &levels[0][i * 2 + 1]);
                    i += 1;
                }
                if odd == 1 {
                    level[i] = levels[0][i * 2];
                }
                levels.push_front(level);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn verify<'a>(&self, leaves: &mut impl Iterator<Item = &'a [u8]>) -> bool {
        let other = Tree::new(leaves);
        *self == other
    }

    pub(crate) fn commitment(&self) -> Commitment {
        Commitment {
            root: self.root,
            num_items: self.num_items(),
        }
    }
}

#[test]
fn test_tree() {
    fn test_verify(v: &Vec<&[u8]>) {
        let tree = Tree::new(&mut v.clone().into_iter());
        assert!(tree.verify(&mut v.clone().into_iter()));
    }

    fn modify_frontier(frontier: &mut Vec<ProofNode>) -> bool {
        if frontier.len() > 0 {
            if frontier[0] == ProofNode::NodeWithoutSibling {
                frontier[0] = ProofNode::LeftChildWithSibling(blake3::hash(b"hello, world"));
            } else {
                frontier[0] = ProofNode::NodeWithoutSibling;
            }
            true
        } else {
            false
        }
    }

    fn test_prove(v: &Vec<&[u8]>) {
        let tree = Tree::new(&mut v.clone().into_iter());
        let mut proof = tree.prove(v[0].into(), 0).unwrap();
        let v: Vec<u8> = (&proof).into();
        let v_ref: &[u8] = &v;
        let proof_2: Proof = v_ref.try_into().unwrap();
        assert_eq!(proof, proof_2);
        let commitment = tree.commitment();
        assert!(commitment.verify(&proof));
        if modify_frontier(&mut proof.frontier) {
            assert!(!commitment.verify(&proof));
        }
    }

    let test_vectors: Vec<Vec<&[u8]>> = vec![
        vec![b"hello, world"],
        vec![b"one", b"two", b"three"],
        vec![b"one", b"two"],
        vec![b"hey"; 1000],
    ];
    for test_vector in test_vectors {
        test_verify(&test_vector);
        test_prove(&test_vector);
    }
}
