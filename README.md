# blake3-lamport-signatures

Lamport signatures implemented using the `blake3` cryptographic
hash function.

```rust

let secret_key = SecretKey::generate()?;
let public_key = SecretKey::public_key();
let message = b"Yeah, I said it";
let signature = secret_key.sign(message);

assert!(public_key.verify(message, &signature));
```
