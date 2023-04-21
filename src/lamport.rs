use blake3::hash;
use rand::rngs::OsRng;
use rand::Fill;

/// A private key is what you generate and keep in order to sign things.
/// From it, you can generate a [`PublicKey`] and send that to others,
/// allowing them to verify your signatures down the line.
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub struct PrivateKey {
    left: [u8; 8192],
    right: [u8; 8192],
}

impl From<&[u8; 16384]> for PrivateKey {
    fn from(value: &[u8; 16384]) -> Self {
        let mut left = [0u8; 8192];
        let mut right = [0u8; 8192];
        for i in 0..8192 {
            left[i] = value[i];
        }
        for i in 0..8192 {
            right[i] = value[i + 8192];
        }
        PrivateKey { left, right }
    }
}

impl From<&PrivateKey> for [u8; 16384] {
    /// Turns the private key into a single byte array
    fn from(private_key: &PrivateKey) -> [u8; 16384] {
        let mut out = [0u8; 16384];
        for i in 0..8192 {
            out[i] = private_key.left[i];
        }
        for i in 0..8192 {
            out[i + 8192] = private_key.right[i];
        }
        out
    }
}

impl PrivateKey {
    /// Generates a new private key using the operating system random
    /// number generator.
    pub fn generate() -> Result<PrivateKey, rand::Error> {
        let mut left = [0u8; 8192];
        let mut right = [0u8; 8192];
        left.try_fill(&mut OsRng)?;
        right.try_fill(&mut OsRng)?;
        Ok(PrivateKey { left, right })
    }

    /// Creates the [`PublicKey`] associated with this [`PrivateKey`].
    pub fn public_key(&self) -> PublicKey {
        let mut public_key: PublicKey = PublicKey {
            left_hashes: [[0u8; 32]; 256],
            right_hashes: [[0u8; 32]; 256],
        };
        for ((lhash, rhash), i) in self
            .left
            .chunks(32)
            .map(hash)
            .zip(self.right.chunks(32).map(hash))
            .zip(0..)
        {
            public_key.left_hashes[i] = lhash.as_bytes().clone();
            public_key.right_hashes[i] = rhash.as_bytes().clone();
        }
        public_key
    }

    /// Signs the message, producing a [`Signature`] which another party would
    /// be able to [`PublicKey::verify`] with access to the [`PublicKey`] generated
    /// from this [`PrivateKey`] with [`PrivateKey::public_key`].
    pub fn sign<A: AsRef<[u8]>>(&self, message: A) -> Signature {
        let hash = hash(message.as_ref());
        let mut signature: Signature = Signature {
            exposed: [0u8; 8192],
        };
        for (chunk, i) in signature.exposed.chunks_mut(32).zip(0..) {
            // TODO(sam) conditional, does this enable timing attacks?
            let side = if bit_of_byteslice(i, hash.as_bytes()) {
                self.left
            } else {
                self.right
            };
            chunk.clone_from_slice(&side[i * 32..(i + 1) * 32]);
        }
        signature
    }
}

fn bit_of_byteslice(index: usize, bytes: &[u8]) -> bool {
    let byte = bytes[index.div_euclid(8)];
    bit_of_byte(index.rem_euclid(8), byte)
}

fn bitmask_for(index: usize) -> u8 {
    match index {
        0 => 0b00000001,
        1 => 0b00000010,
        2 => 0b00000100,
        3 => 0b00001000,
        4 => 0b00010000,
        5 => 0b00100000,
        6 => 0b01000000,
        7 => 0b10000000,
        _ => bitmask_for(index.rem_euclid(8)),
    }
}

#[test]
fn test_bit_of_byteslice() {
    assert!(!bit_of_byteslice(0, b"\x00\x00"));
    assert!(bit_of_byteslice(0, b"\xFF\x00"));
    assert!(!bit_of_byteslice(9, b"\xFF\x00"));
    assert!(bit_of_byteslice(9, b"\xFF\x07"));
}

fn bit_of_byte(index: usize, byte: u8) -> bool {
    let mask = bitmask_for(index);
    byte.to_le() & mask == mask
}

#[test]
fn test_bit_of_byte() {
    assert!(bit_of_byte(0, 0b00000001));
    assert!(!bit_of_byte(0, 0b00000010));
}

/// The public key associated with a given [`PrivateKey`], allowing any
/// owner to [`PublicKey::verify`] a [`Signature`] produced by that
/// [`PrivateKey`].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct PublicKey {
    left_hashes: [[u8; 32]; 256],
    right_hashes: [[u8; 32]; 256],
}

impl From<&[u8; 16384]> for PublicKey {
    fn from(value: &[u8; 16384]) -> Self {
        let mut left_hashes = [[0u8; 32]; 256];
        let mut right_hashes = [[0u8; 32]; 256];

        let mut i = 0;
        for j in 0..256 {
            for k in 0..32 {
                left_hashes[j][k] = value[i];
                i += 1;
            }
        }

        for j in 0..256 {
            for k in 0..32 {
                right_hashes[j][k] = value[i];
                i += 1;
            }
        }

        PublicKey {
            left_hashes,
            right_hashes,
        }
    }
}

impl From<&PublicKey> for [u8; 16384] {
    fn from(value: &PublicKey) -> Self {
        let mut out = [0u8; 16384];
        let mut i = 0;
        for j in 0..256 {
            for k in 0..32 {
                out[i] = value.left_hashes[j][k];
                i += 1;
            }
        }
        for j in 0..256 {
            for k in 0..32 {
                out[i] = value.right_hashes[j][k];
                i += 1;
            }
        }
        out
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 16384] {
        self.into()
    }

    pub fn verify<A: AsRef<[u8]>>(&self, message: A, signature: &Signature) -> bool {
        let msg_hash = hash(message.as_ref());
        signature
            .exposed
            .chunks(32)
            .zip(0..)
            .fold(true, |acc, (chunk, i)| {
                let public_hash = if bit_of_byteslice(i, msg_hash.as_bytes()) {
                    self.left_hashes[i]
                } else {
                    self.right_hashes[i]
                };
                acc && hash(chunk).as_bytes() == &public_hash
            })
    }
}

/// The result of [`PrivateKey::sign`]ing a message. Can be verified
/// to be from the [`PrivateKey`] associated with a [`PublicKey`]
/// if you have that public key, the message, along with the signature.
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub struct Signature {
    exposed: [u8; 8192],
}

impl From<[u8; 8192]> for Signature {
    fn from(exposed: [u8; 8192]) -> Self {
        Signature { exposed }
    }
}

impl From<Signature> for [u8; 8192] {
    fn from(signature: Signature) -> Self {
        signature.exposed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn end_to_end() -> Result<(), Box<dyn std::error::Error>> {
        let private = PrivateKey::generate()?;
        let public_key = private.public_key();
        let message = b"Hello, world!";

        let signature = private.sign(message);
        assert!(public_key.verify(message, &signature));

        let faulty_message = b"Hello, not world!";
        assert!(!public_key.verify(faulty_message, &signature));

        let faulty_signature = private.sign(faulty_message);
        assert!(!public_key.verify(message, &faulty_signature));

        assert!(public_key.verify(faulty_message, &faulty_signature));
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 999, .. ProptestConfig::default()
        })]

        #[test]
        fn really_works(s in "\\PC*") {
            let private = PrivateKey::generate()?;
            let public_key = private.public_key();
            let message = s.as_bytes();

            let signature = private.sign(message);
            assert!(public_key.verify(message, &signature));
        }

    }
}
