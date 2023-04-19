pub mod internal;

use crate::lamport;
use crate::merkle::internal::*;

/// A public key is the Merkle root of the tree in your [`PrivateKey`].
pub struct PublicKey(Commitment);

impl PublicKey {
    pub fn verify<A: AsRef<[u8]>>(&self, message: A, signature: &Signature) -> bool {
        self.0.verify(&signature.2) && signature.1.verify(message, &signature.0)
    }
}

/// A private key consists of a Merkle tree committing to a sequence
/// of Lamport public keys, one for each message you plan to sign.
pub struct PrivateKey(Vec<lamport::PrivateKey>, Tree, usize);

/// A signature consists of a lamport signature and a merkle proof of the
/// public key used.
pub struct Signature(lamport::Signature, lamport::PublicKey, Proof);

impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.1.commitment())
    }

    pub fn generate(n: usize) -> Result<PrivateKey, rand::Error> {
        let private_keys: Result<Vec<lamport::PrivateKey>, rand::Error> =
            (0..n).map(|_i| lamport::PrivateKey::generate()).collect();
        let private_keys = private_keys?;
        let encoded_public_keys: Vec<Vec<u8>> = private_keys
            .iter()
            .map(|private_key| {
                private_key
                    .public_key()
                    .to_bytes()
                    .iter()
                    .copied()
                    .collect()
            })
            .collect();
        let tree = Tree::new(&mut encoded_public_keys.iter().map(|v| v.as_slice()));
        Ok(PrivateKey(private_keys, tree, 0))
    }

    pub fn sign<A: AsRef<[u8]>>(&mut self, message: A) -> Option<Signature> {
        let index = self.2;

        if index >= self.0.len() {
            return None;
        }

        let merkle_tree = &self.1;
        let lamport_private_key = &self.0[index];
        let lamport_public_key = lamport_private_key.public_key();
        let lamport_public_key_bytes = lamport_public_key.to_bytes().iter().copied().collect();

        let proof = merkle_tree.prove(lamport_public_key_bytes, index as u64);

        proof.map(|proof| {
            let lamport_signature = lamport_private_key.sign(message);
            Signature(lamport_signature, lamport_public_key, proof)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::proptest;

    #[test]
    fn test_generation() {
        let _private_key = PrivateKey::generate(1000);
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 999, .. ProptestConfig::default()
        })]

        #[test]
        fn test_merkle_signatures(s in "\\PC*") {
            let mut private_key = PrivateKey::generate(1).unwrap();
            let public_key = private_key.public_key();
            let signature = private_key.sign(&s.as_bytes()).unwrap();
            assert!(public_key.verify(s.as_bytes(), &signature));

        }
    }
}