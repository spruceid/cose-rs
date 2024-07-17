# Cbor Object Signing and Encryption (COSE)

Pure Rust implementation of [RFC-8152](https://www.rfc-editor.org/info/rfc8152),
using the `Signer` and `Verifier` traits from RustCrypto's `signature` crate,
`Hmac*` from `hmac` crate and `cbc_mac` with `aes` crates for `AES-CBC-MAC` to abstract over cryptographic backend.

Currently only implements `COSE_Sign1` and `COSE_MAC0`.
