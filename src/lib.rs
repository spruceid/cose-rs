//! Cbor Object Signing and Encryption (COSE)
//!
//! Pure rust implementation of [RFC-8152](https://www.rfc-editor.org/info/rfc8152), using the `Signer`
//! and `Verifier` traits from RustCrypto's `signature` crate to abstract over cryptographic backend.

/// COSE algorithms.
#[allow(non_camel_case_types)]
pub mod algorithm;
mod header_map;
mod protected;
/// Implementation of COSE_Sign1.
pub mod sign1;

pub use sign1::CoseSign1;
