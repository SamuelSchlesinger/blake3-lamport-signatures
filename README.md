# blake3-lamport-signatures

Lamport signatures implemented using the `blake3` cryptographic
hash function. This is an incredibly inefficient digital signature protocol
and shouldn't be used under almost all circumstances, its main benefit being
its simplicity and flexibility. The technique can be extended in all sorts
of interesting ways to provide tradeoffs between signature size and private/public
key size, with one famous extension being called a Merkle signature.

```rust

let secret_key = SecretKey::generate()?;
let public_key = SecretKey::public_key();
let message = b"Yeah, I said it";
let signature = secret_key.sign(message);

assert!(public_key.verify(message, &signature));
```

## Communication

There is a natural two-party verified communication protocol associated with
lamport signatures. Alice and Bob start with preshared `PublicKey`s, and each
time they send a message, they include the `PublicKey` for the next message.

## Acknowledgements

Leslie Lamport is a really cool dude.
