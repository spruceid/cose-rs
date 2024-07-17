#[cfg(feature = "async")]
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::fmt::Debug;

use crate::algorithm::{Algorithm, SignatureAlgorithm};
use crate::{header_map::HeaderMap, protected::Protected};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CoseInner(
    pub(crate) Protected,
    pub(crate) HeaderMap,
    pub(crate) Option<ByteBuf>,
    pub(crate) ByteBuf,
);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PreparedCose {
    pub(crate) tagged: bool,
    pub(crate) protected: Protected,
    pub(crate) unprotected: HeaderMap,
    pub(crate) payload: Option<ByteBuf>,
    pub(crate) signature_payload: Vec<u8>,
}

/// Builder for COSE object.
#[derive(Clone, Debug, Default)]
pub(crate) struct BuilderCose {
    pub(crate) tagged: bool,
    pub(crate) detached: bool,
    pub(crate) protected: Protected,
    pub(crate) unprotected: HeaderMap,
    pub(crate) external_aad: Option<Vec<u8>>,
    pub(crate) payload: Option<ByteBuf>,
}

#[derive(Debug)]
pub enum VerificationResult<E: std::error::Error> {
    Success,
    Failure(String),
    Error(E),
}

impl<E: std::error::Error> VerificationResult<E> {
    /// Result of verification.
    ///
    /// False implies the signature is inauthentic or the verification algorithm encountered an
    /// error.
    pub fn success(&self) -> bool {
        matches!(self, VerificationResult::Success)
    }

    /// Translate to a [`Result`].
    ///
    /// Converts failure reasons and errors into a String.
    pub fn to_result(self) -> Result<(), String> {
        match self {
            VerificationResult::Success => Ok(()),
            VerificationResult::Failure(reason) => Err(reason),
            VerificationResult::Error(e) => Err(format!("{}", e)),
        }
    }

    /// Retrieve the error if the verification algorithm encountered an error.
    pub fn to_error(self) -> Option<E> {
        match self {
            VerificationResult::Error(e) => Some(e),
            _ => None,
        }
    }
}

impl BuilderCose {
    /// Set the tagged flag, so that the generated `COSE_*` is serialized with cbor tag 18.
    pub fn tagged(mut self) -> Self {
        self.tagged = true;
        self
    }

    /// Set the detached flag, so that the payload will not be included in the `COSE_*`.
    pub fn detached(mut self) -> Self {
        self.detached = true;
        self
    }

    /// Set the protected headers.
    pub fn protected<P>(mut self, protected: P) -> Self
    where
        P: Into<Protected>,
    {
        self.protected = protected.into();
        self
    }

    /// Set the unprotected headers.
    pub fn unprotected<H>(mut self, unprotected: H) -> Self
    where
        H: Into<HeaderMap>,
    {
        self.unprotected = unprotected.into();
        self
    }

    /// Set the externally supplied data.
    ///
    /// Add some additional data to be signed over that is transported separately from the
    /// `COSE_*` (RFC-8152#Section4.3).
    pub fn external_aad<B>(mut self, external_aad: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        self.external_aad = Some(external_aad.into());
        self
    }

    /// Set the payload.
    pub fn payload<P>(mut self, p: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        self.payload = Some(ByteBuf::from(p));
        self
    }

    /// Set the signature algorithm in the protected headers.
    ///
    /// This is not required if signing directly as it can be derived from the signer,
    /// but should be set if using [`Builder::prepare`] and producing the signature remotely.
    pub fn signature_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.protected.insert_i(1, algorithm.value().into());
        self
    }

    /// Prepare a `COSE_*` for remote signing.
    pub(crate) fn prepare<E: std::error::Error>(
        self,
        signature_payload: impl FnOnce(&Protected, Option<Vec<u8>>, &[u8]) -> Result<Vec<u8>, E>,
    ) -> Result<PreparedCose, E> {
        let payload = self
            .payload
            // If payload is None, use cbor null as payload.
            .unwrap_or_else(|| ByteBuf::from([246u8]));
        let signature_payload =
            signature_payload(&self.protected, self.external_aad, payload.as_ref())?;
        let prepared = if self.detached {
            PreparedCose {
                tagged: self.tagged,
                protected: self.protected,
                unprotected: self.unprotected,
                payload: None,
                signature_payload,
            }
        } else {
            PreparedCose {
                tagged: self.tagged,
                protected: self.protected,
                unprotected: self.unprotected,
                payload: Some(payload),
                signature_payload,
            }
        };
        Ok(prepared)
    }
}

/// Sign the provided message bytestring using [`Self`] (e.g., a cryptographic key,
/// connection to an `HSM`, `MAC` or `AES-CBC-MAC`), returning a digital signature or `MAC`.
pub trait Signer<S, E: std::error::Error>: SignatureAlgorithm {
    /// Sign the given message and return a digital signature or `MAC`
    fn sign(&self, msg: &[u8]) -> S {
        self.try_sign(msg)
            .expect("signature or `MAC` operation failed")
    }

    /// Attempt to sign the given message, returning a digital signature or `MAC` on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g., cloud KMS, HSMs, or other hardware tokens.
    fn try_sign(&self, msg: &[u8]) -> Result<S, E>;
}

/// Verify the provided message bytestring using `Self` (e.g., a public key or `MAC` algorithm).
pub trait Verifier<S, E: std::error::Error>: SignatureAlgorithm {
    /// Use [`Self`] to verify that the provided signature for a given message
    /// bytestring is authentic.
    ///
    /// Returns [`E`] if it is inauthentic, or otherwise returns `()`.
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), E>;
}

#[cfg(feature = "async")]
/// Asynchronously sign the provided message bytestring using [`Self`]
/// (e.g., client for a `Cloud KMS`, `HSM` or `MAC`), returning a digital signature.
///
/// This trait is an async equivalent of the [`Signer`] trait.
#[async_trait]
pub trait AsyncSigner<S, E>: SignatureAlgorithm
where
    Self: Send + Sync,
    S: Send + 'static,
    E: std::error::Error,
{
    /// Attempt to sign the given message, returning a digital signature or `MAC` on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g., `cloud KMS`, `HSMs`, `MAC` or other hardware tokens.
    async fn sign_async(&self, msg: &[u8]) -> Result<S, E>;
}

#[cfg(feature = "async")]
#[async_trait]
impl<S, T, E> AsyncSigner<S, E> for T
where
    S: Send + 'static,
    T: Signer<S, E> + Send + Sync,
    E: std::error::Error,
{
    async fn sign_async(&self, msg: &[u8]) -> Result<S, E> {
        self.try_sign(msg)
    }
}

/// Support for decoding/encoding signatures or `MAC` as bytes.
pub trait SignatureEncoding:
    Clone + Sized + for<'a> TryFrom<&'a [u8]> + TryInto<Self::Repr>
{
    /// Byte representation of a signature.
    type Repr: 'static + AsRef<[u8]> + Clone + Send + Sync;

    /// Encode signature or `MAC` as its byte representation.
    fn to_bytes(&self) -> Self::Repr {
        self.clone()
            .try_into()
            .ok()
            .expect("signature encoding error")
    }

    /// Encode signature or `MAC` as a byte vector.
    fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }

    /// Get the length of this signature or `MAC` when encoded.
    fn encoded_len(&self) -> usize {
        self.to_bytes().as_ref().len()
    }
}

// impl<T: signature::SignatureEncoding> SignatureEncoding for T {
//     type Repr = T::Repr;
// }

impl SignatureEncoding for Vec<u8> {
    type Repr = Vec<u8>;
}
