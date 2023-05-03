# blake3-lamport-signatures

[![Rust](https://github.com/SamuelSchlesinger/blake3-lamport-signatures/actions/workflows/rust.yml/badge.svg)](https://github.com/SamuelSchlesinger/blake3-lamport-signatures/actions/workflows/rust.yml)

Lamport, as well as Lamport-Merkle, signatures implemented using the `blake3`
cryptographic hash function. This is an incredibly inefficient digital
signature protocol and shouldn't be used under almost all circumstances, its
main benefit being its simplicity and flexibility.

Lamport keypairs should only be used to sign one message, while you can specify a
number of messages to support in a Lamport-Merkle keypair.

```rust
use blake3_lamport_signatures::lamport;

let private_key = lamport::PrivateKey::generate()?;
let public_key = private_key.public_key();
let message = b"Yeah, I said it";
let signature = private_key.sign(message);

assert!(public_key.verify(message, &signature));

use blake3_lamport_signatures::merkle;
// generate a Merkle-Lamport private key capable of signing 100 messages
let mut private_key = merkle::PrivateKey::generate(100);
let public_key = private_key.public_key();
let message = b"And I'll say it again!";
let signature = private_key.sign(message);

assert!(public_key.verify(message, &signature);
```

## Communication

There is a natural two-party verified communication protocol associated with
lamport signatures. Alice and Bob start with preshared `PublicKey`s, and each
time they send a message, they include the `PublicKey` for the next message.

## Merkle Signer

There is an included program to generate and use Merkle signatures in
`blake3-merkle-signer`. The API is:

```
Usage: signer <COMMAND>

Commands:
  key-gen
  sign
  verify
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Acknowledgements

Leslie Lamport is a really cool dude.
