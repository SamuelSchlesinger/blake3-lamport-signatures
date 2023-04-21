pub mod internal;

use crate::lamport;
use crate::merkle::internal::*;

pub use crate::merkle::internal::ProofDecodingError;

/// A public key is the Merkle root of the tree in your [`PrivateKey`].
pub struct PublicKey(Commitment);

impl From<[u8; 40]> for PublicKey {
    fn from(value: [u8; 40]) -> Self {
        let mut hash_arr: [u8; 32] = [0u8; 32];
        for i in 0..32 {
            hash_arr[i] = value[i];
        }
        let mut u64_arr: [u8; 8] = [0u8; 8];
        for i in 0..8 {
            u64_arr[i] = value[32 + i];
        }
        PublicKey(Commitment {
            root: blake3::Hash::from(hash_arr),
            num_items: u64::from_be_bytes(u64_arr),
        })
    }
}

impl From<PublicKey> for [u8; 40] {
    fn from(value: PublicKey) -> Self {
        let mut arr = [0u8; 40];
        for i in 0..32 {
            arr[i] = value.0.root.as_bytes()[i];
        }
        let u64_arr = value.0.num_items.to_be_bytes();
        for i in 0..8 {
            arr[i + 32] = u64_arr[i];
        }
        arr
    }
}

impl PublicKey {
    pub fn verify<A: AsRef<[u8]>>(&self, message: A, signature: &Signature) -> bool {
        self.0.verify(&signature.2) && signature.1.verify(message, &signature.0)
    }
}

/// A private key consists of a Merkle tree committing to a sequence
/// of Lamport public keys, one for each message you plan to sign.
pub struct PrivateKey(Vec<lamport::PrivateKey>, Tree, usize);

impl From<(Vec<lamport::PrivateKey>, usize)> for PrivateKey {
    fn from((private_keys, current_index): (Vec<lamport::PrivateKey>, usize)) -> Self {
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
        PrivateKey(private_keys, tree, current_index)
    }
}

/// A signature consists of a lamport signature and a merkle proof of the
/// public key used.
#[derive(Debug, Eq, PartialEq)]
pub struct Signature(lamport::Signature, lamport::PublicKey, Proof);

#[derive(Debug)]
pub enum SignatureDecodingError {
    NotEnoughInput(usize),
    MerkleProofDecodingError(ProofDecodingError),
}

impl From<&Signature> for Vec<u8> {
    fn from(sig: &Signature) -> Self {
        let mut output = Vec::new();
        let lamport_sig_bytes: [u8; 8192] = sig.0.clone().into();
        output.extend(lamport_sig_bytes.into_iter());

        let lamport_pub_key_bytes: [u8; 16384] = (&sig.1).into();
        output.extend(lamport_pub_key_bytes.into_iter());

        let proof_bytes: Vec<u8> = (&sig.2).into();
        output.extend(proof_bytes.into_iter());

        output
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureDecodingError;
    fn try_from(signature_bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut i = 0;
        let next_byte = |i: &mut usize| {
            if let Some(b) = signature_bytes.get(*i) {
                *i += 1;
                Ok(*b)
            } else {
                Err(SignatureDecodingError::NotEnoughInput(
                    signature_bytes.len(),
                ))
            }
        };
        let mut lamport_signature_bytes = [0u8; 8192];
        for j in 0..8192 {
            lamport_signature_bytes[j] = next_byte(&mut i)?;
        }
        let lamport_signature = lamport::Signature::from(lamport_signature_bytes);

        let mut lamport_public_key_bytes = [0u8; 16384];
        for j in 0..16384 {
            lamport_public_key_bytes[j] = next_byte(&mut i)?;
        }
        let lamport_public_key = lamport::PublicKey::from(&lamport_public_key_bytes);

        let proof = Proof::try_from(&signature_bytes[i..])
            .map_err(|e| SignatureDecodingError::MerkleProofDecodingError(e))?;

        Ok(Signature(lamport_signature, lamport_public_key, proof))
    }
}

impl PrivateKey {
    pub fn inner_keys(&self) -> &Vec<lamport::PrivateKey> {
        &self.0
    }

    pub fn current_index(&self) -> usize {
        self.2
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.1.commitment())
    }

    pub fn generate(n: usize) -> Result<PrivateKey, rand::Error> {
        let private_keys: Result<Vec<lamport::PrivateKey>, rand::Error> =
            (0..n).map(|_i| lamport::PrivateKey::generate()).collect();
        let private_keys = private_keys?;
        Ok((private_keys, 0).into())
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
            let signature_bytes: Vec<u8> = (&signature).into();
            let signature_bytes_ref: &[u8] = &signature_bytes;
            let signature_2: Signature = signature_bytes_ref.try_into().unwrap();
            assert_eq!(signature, signature_2);
            assert!(public_key.verify(s.as_bytes(), &signature));

        }
    }
}
