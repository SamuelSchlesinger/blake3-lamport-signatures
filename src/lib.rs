/// An implementation of Lamport signatures
pub mod lamport;
/// Builds off of the Lamport signatures by implementing a
/// Merkle commitment to a vector of Lamport public keys,
/// with a Merkle proof coupled with a Lamport signature
/// comprising a signature
pub mod merkle;
