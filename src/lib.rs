use blake3::hash;
use rand::rngs::OsRng;
use rand::Fill;

/// A secret key is what you generate and keep in order to sign things.
/// From it, you can generate a [`PublicKey`] and send that to others,
/// allowing them to verify your signatures down the line.
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub struct SecretKey {
    left: [u8; 8192],
    right: [u8; 8192],
}

impl SecretKey {
    /// Generates a new secret key using the operating system random
    /// number generator.
    pub fn generate() -> Result<SecretKey, rand::Error> {
        let mut left = [0u8; 8192];
        let mut right = [0u8; 8192];
        left.try_fill(&mut OsRng)?;
        right.try_fill(&mut OsRng)?;
        Ok(SecretKey { left, right })
    }

    /// Creates the [`PublicKey`] associated with this [`SecretKey`].
    pub fn public_key(&self) -> Box<PublicKey> {
        let mut public_key: Box<PublicKey> = Box::new(PublicKey {
            left_hashes: unsafe { std::mem::MaybeUninit::uninit().assume_init() },
            right_hashes: unsafe { std::mem::MaybeUninit::uninit().assume_init() },
        });
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
    /// from this [`SecretKey`] with [`SecretKey::public_key`].
    pub fn sign<A: AsRef<[u8]>>(&self, message: A) -> Box<Signature> {
        let hash = hash(message.as_ref());
        let mut signature: Box<Signature> = Box::new(Signature {
            exposed: unsafe { std::mem::MaybeUninit::uninit().assume_init() },
        });
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

/// The public key associated with a given [`SecretKey`], allowing any
/// owner to [`PublicKey::verify`] a [`Signature`] produced by that
/// [`SecretKey`].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct PublicKey {
    left_hashes: [[u8; 32]; 256],
    right_hashes: [[u8; 32]; 256],
}

impl PublicKey {
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

/// The result of [`SecretKey::sign`]ing a message. Can be verified
/// to be from the [`SecretKey`] associated with a [`PublicKey`]
/// if you have that public key, the message, along with the signature.
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub struct Signature {
    exposed: [u8; 8192],
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn end_to_end() -> Result<(), Box<dyn std::error::Error>> {
        let secret = SecretKey::generate()?;
        let public_key = secret.public_key();
        let message = b"Hello, world!";

        let signature = secret.sign(message);
        assert!(public_key.verify(message, &signature));

        let faulty_message = b"Hello, not world!";
        assert!(!public_key.verify(faulty_message, &signature));

        let faulty_signature = secret.sign(faulty_message);
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
            let secret = SecretKey::generate()?;
            let public_key = secret.public_key();
            let message = s.as_bytes();

            let signature = secret.sign(message);
            assert!(public_key.verify(message, &signature));
        }

    }
}
