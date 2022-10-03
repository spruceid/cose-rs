# Cbor Object Signing and Encryption (COSE)

Pure rust implementation of [RFC-8152](https://www.rfc-editor.org/info/rfc8152), using the `Signer` and `Verifier` traits from RustCrypto's `signature` crate to abstract over cryptographic backend.

Currently only implements COSE_Sign1.
