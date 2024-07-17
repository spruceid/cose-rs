use crate::algorithm::Algorithm;
#[cfg(feature = "async")]
use crate::common::AsyncSigner;
pub use crate::common::VerificationResult;
use crate::common::{BuilderCose, CoseInner, PreparedCose, SignatureEncoding, Signer, Verifier};
use crate::cwt::{self, ClaimsSet};
pub use crate::{header_map::HeaderMap, protected::Protected};
use aes::cipher::InvalidLength;
use aes::{Aes128, Aes256};
use cbc_mac::CbcMac;
use digest::block_buffer::Eager;
use digest::core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore};
use digest::typenum::{IsLess, Le, NonZero, U256};
use digest::{HashMarker, Mac};
use hmac::Hmac;
use serde::{
    de::{self, Error as DeError},
    ser, Deserialize, Serialize,
};
use serde_bytes::ByteBuf;
use serde_cbor::{tags::Tagged, Value};
use sha2::{Sha256, Sha384, Sha512};
use std::convert::Infallible;

pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha384 = Hmac<Sha384>;
pub type HmacSha512 = Hmac<Sha512>;

pub type Aes128CbcMac = CbcMac<Aes128>;
pub type Aes256CbcMac = CbcMac<Aes256>;

/// COSE_Mac0 implementation.
#[derive(Clone, Debug)]
pub struct CoseMac0 {
    tagged: bool,
    inner: CoseInner,
}

/// Prepared `COSE_Mac0` for remote signing.
///
/// To produce a `COSE_Mac0,` do the following:
///
/// 1. Set the signature algorithm in the builder using [`Builder::signature_algorithm`].
/// 2. Produce a signature remotely, according to the chosen signature algorithm,
///    using the [`PreparedCoseMac0::signature_payload`] as the payload.
/// 3. Generate the `COSE_Mac0` by passing the produced signature into
///    [`PreparedCoseMac0::finalize`].
///
/// Example:
///
/// ```ignore
/// let builder = builder.signature_algorithm(Algorithm::SHA_256);
/// let prepared: PreparedCoseMac0 = builder.prepare()?;
/// let signature_payload = prepared.signature_payload();
/// let signature = /* produce a signature according to `HMAC SHA_256` using signature_payload as the payload */;
/// let cose_mac0: CoseMac0 = prepared.finalize(signature);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedCoseMac0(PreparedCose);

/// Builder for COSE_Mac0.
#[derive(Clone, Debug, Default)]
pub struct Builder(BuilderCose);

/// Errors that can occur when building, signing or verifying a `COSE_Mac0`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the COSE_Mac0 has an attached payload but an detached payload was provided to the verify function")]
    DoublePayload,
    #[error("the COSE_Mac0 has a detached payload which was not provided to the verify function")]
    NoPayload,
    #[error("signature did not match the structure expected by the verifier: {0}")]
    MalformedSignature(Infallible),
    #[error("error occurred when signing COSE_Mac0: {0}")]
    Signing(hmac::digest::MacError),
    #[error("unable to serialize COSE_Mac0 protected headers: {0}")]
    UnableToSerializeProtected(serde_cbor::Error),
    #[error("unable to serialize COSE_Mac0 signature payload: {0}")]
    UnableToSerializeSignaturePayload(serde_cbor::Error),
    #[error("unable to set ClaimsSet: {0}")]
    UnableToDeserializeIntoClaimsSet(serde_cbor::Error),
    #[error("unable to deserialize COSE key: {0}")]
    UnableToDeserializeCoseKey(serde_cbor::Error),
    #[error("invalid length COSE key: {0}")]
    InvalidLengthCoseKey(InvalidLength),
    #[error("invalid kty COSE key: {0}")]
    InvalidKtyCoseKey(String),
    #[error("invalid alg COSE key: {0}")]
    InvalidAlgCoseKey(String),
}

impl From<Infallible> for Error {
    fn from(value: Infallible) -> Self {
        Error::MalformedSignature(value)
    }
}

/// Result with error type: [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl CoseMac0 {
    /// Construct a builder for a new `COSE_Mac0`.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Verify that the `MAC` or `AES-CBC-MAC` of a `COSE_Mac0` is authentic.
    pub fn verify<'a, V, S>(
        &'a self,
        verifier: &V,
        detached_payload: Option<Vec<u8>>,
        external_aad: Option<Vec<u8>>,
    ) -> VerificationResult<Error>
    where
        V: Verifier<S, Error>,
        S: TryFrom<&'a [u8]>,
        S::Error: Into<Error>,
    {
        if let Some(value) = self.inner.0.get_i(1) {
            match value {
                Value::Integer(alg_value) => {
                    if verifier.algorithm().value() as i128 != *alg_value {
                        return VerificationResult::Failure(
                            "algorithm in protected headers did not match verifier's algorithm"
                                .into(),
                        );
                    }
                }
                Value::Text(alg_value_str) => {
                    // If alg header does not parse as an i32; ignore and carry on verification.
                    if let Ok(alg_value) = alg_value_str.parse::<i32>() {
                        if verifier.algorithm().value() != alg_value {
                            return VerificationResult::Failure(
                                "algorithm in protected headers did not match verifier's algorithm"
                                    .into(),
                            );
                        }
                    }
                }
                // Unexpected type for algorithm header; ignore and carry on verification.
                _ => {}
            }
        }

        let payload = match (self.inner.2.as_ref(), detached_payload.as_ref()) {
            (None, None) => return VerificationResult::Error(Error::NoPayload),
            (Some(attached), None) => attached,
            (None, Some(detached)) => detached,
            _ => return VerificationResult::Error(Error::DoublePayload),
        };

        let signature = match S::try_from(self.inner.3.as_ref()) {
            Ok(sig) => sig,
            Err(_) => return VerificationResult::Failure("invalid signature encoding".to_string()),
        };

        let signature_payload = match signature_payload(&self.inner.0, external_aad, payload) {
            Ok(data) => data,
            Err(e) => return VerificationResult::Error(e),
        };

        match verifier.verify(&signature_payload, &signature) {
            Ok(()) => VerificationResult::Success,
            Err(e) => VerificationResult::Failure(format!("signature is not authentic: {}", e)),
        }
    }

    /// Retrieve the protected headers.
    pub fn protected(&self) -> &Protected {
        &self.inner.0
    }

    /// Retrieve the unprotected headers.
    pub fn unprotected(&self) -> &HeaderMap {
        &self.inner.1
    }

    /// Retrieve a mutable reference to the unprotected headers.
    pub fn unprotected_mut(&mut self) -> &mut HeaderMap {
        &mut self.inner.1
    }

    /// Retrieve the payload if it is attached.
    pub fn payload(&self) -> Option<&ByteBuf> {
        self.inner.2.as_ref()
    }

    /// Retrieve the CWT claims set.
    pub fn claims_set(&self) -> Result<Option<ClaimsSet>> {
        match self.payload() {
            None => Ok(None),
            Some(payload) => serde_cbor::from_slice(payload).map_or_else(
                |e| Err(Error::UnableToDeserializeIntoClaimsSet(e)),
                |c| Ok(Some(c)),
            ),
        }
    }
}

impl ser::Serialize for CoseMac0 {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if self.tagged {
            Tagged::<&CoseInner>::new(Some(18), &self.inner)
        } else {
            Tagged::<&CoseInner>::new(None, &self.inner)
        }
        .serialize(s)
    }
}

impl<'de> de::Deserialize<'de> for CoseMac0 {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let cose = Tagged::<CoseInner>::deserialize(d)?;
        let tagged = match cose.tag {
            None => false,
            Some(18) => true,
            Some(n) => {
                return Err(D::Error::custom(format!(
                    "unable to deserialize CoseMac0: expected tag 18, received tag {}",
                    n
                )))
            }
        };
        Ok(Self {
            tagged,
            inner: cose.value,
        })
    }
}

impl Builder {
    /// Set the CWT claims set.
    pub fn claims_set(self, claims_set: ClaimsSet) -> Result<Self, cwt::Error> {
        let serialized_claims = claims_set.serialize()?;
        Ok(Self(self.0.payload(serialized_claims)))
    }

    /// Set the tagged flag, so that the generated `COSE_Mac0` is serialized with cbor tag 18.
    pub fn tagged(mut self) -> Self {
        self.0 = self.0.tagged();
        self
    }

    /// Set the detached flag, so that the payload will not be included in the `COSE_Mac0`.
    pub fn detached(mut self) -> Self {
        self.0 = self.0.detached();
        self
    }

    /// Set the protected headers.
    pub fn protected<P>(mut self, protected: P) -> Self
    where
        P: Into<Protected>,
    {
        self.0 = self.0.protected(protected);
        self
    }

    /// Set the unprotected headers.
    pub fn unprotected<H>(mut self, unprotected: H) -> Self
    where
        H: Into<HeaderMap>,
    {
        self.0 = self.0.unprotected(unprotected);
        self
    }

    /// Set the externally supplied data.
    ///
    /// Add some additional data to be signed over that is transported separately from the
    /// `COSE_Mac0` (RFC-8152#Section4.3).
    pub fn external_aad<B>(mut self, external_aad: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        self.0 = self.0.external_aad(external_aad);
        self
    }

    /// Set the payload.
    pub fn payload<P>(mut self, p: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        self.0 = self.0.payload(p);
        self
    }

    /// Set the signature algorithm in the protected headers.
    ///
    /// This is not required if signing directly as it can be derived from the signer,
    /// but should be set if using [`Self::prepare`] and producing the signature remotely.
    pub fn signature_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.0 = self.0.signature_algorithm(algorithm);
        self
    }

    /// Prepare a `CoseMac0` for remote signing.
    pub fn prepare(self) -> Result<PreparedCoseMac0> {
        self.0.prepare(signature_payload).map(PreparedCoseMac0)
    }

    /// Sign and generate the `COSE_Mac0`.
    ///
    /// # In the case of `AES-CBC-MAC`
    ///
    /// ## Security Considerations, see [specs](https://datatracker.ietf.org/doc/html/rfc8152#section-9.2.1)
    ///
    /// A number of attacks exist against Cipher Block Chaining Message
    /// Authentication Code (CBC-MAC) that need to be considered.
    ///
    /// - A single key must only be used for messages of a fixed and known
    ///     length.  If this is not the case, an attacker will be able to
    ///     generate a message with a valid tag given two message and tag
    ///     pairs.  This can be addressed by using different keys for messages
    ///     of different lengths.  The current structure mitigates this
    ///     problem, as a specific encoding structure that includes lengths is
    ///     built and signed.  (CMAC also addresses this issue.)
    /// - Cipher Block Chaining (CBC) mode, if the same key is used for both
    ///     encryption and authentication operations, an attacker can produce
    ///     messages with a valid authentication code.
    /// - If the IV can be modified, then messages can be forged.  This is
    ///     addressed by fixing the IV to all zeros.
    pub fn sign<S, Sig>(mut self, s: &S) -> Result<CoseMac0>
    where
        S: Signer<Sig, Error>,
        Sig: SignatureEncoding,
    {
        if self.0.protected.get_i(1).is_none() {
            self.0.protected.insert_i(1, s.algorithm().value().into());
        }
        let prepared = self.prepare()?;
        let signature_payload = prepared.signature_payload();
        let signature = s.try_sign(signature_payload)?.to_vec();
        Ok(prepared.finalize(signature))
    }

    #[cfg(feature = "async")]
    /// Asynchronously sign and generate the `COSE_Mac0`.
    ///
    /// For Security with fixed and variable-length messages in the case of `AES-CBC-MAC` see [`Self::sign`]
    pub async fn sign_async<S, Sig>(mut self, s: &S) -> Result<CoseMac0>
    where
        S: AsyncSigner<Sig, Error>,
        Sig: SignatureEncoding + Send + 'static,
    {
        if self.0.protected.get_i(1).is_none() {
            self.0.protected.insert_i(1, s.algorithm().value().into());
        }
        let prepared = self.prepare()?;
        let signature_payload = prepared.signature_payload();
        let signature = s.sign_async(signature_payload).await?.to_vec();
        Ok(prepared.finalize(signature))
    }
}

impl PreparedCoseMac0 {
    /// Retrieve the signature payload, i.e., the data that must be signed over.
    pub fn signature_payload(&self) -> &[u8] {
        self.0.signature_payload.as_slice()
    }

    /// Finalise the [`Self`] with a remotely signed signature.
    pub fn finalize(self, signature: Vec<u8>) -> CoseMac0 {
        let inner = CoseInner(
            self.0.protected,
            self.0.unprotected,
            self.0.payload,
            ByteBuf::from(signature),
        );
        CoseMac0 {
            tagged: self.0.tagged,
            inner,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CoseKey {
    #[serde(rename = "1")]
    kty: String,
    #[serde(rename = "3")]
    alg: i32,
    #[serde(rename = "-1")]
    key: Vec<u8>,
}

/// Create a new `HMAC` instance from a COSE key. See [specs](https://datatracker.ietf.org/doc/html/rfc8152#section-9.1).
pub fn hmac_from_slice<D>(cbor_key_bytes: &[u8]) -> Result<Hmac<D>>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    // Deserialize CBOR to CoseKey struct
    let cose_key: CoseKey =
        serde_cbor::from_slice(cbor_key_bytes).map_err(Error::UnableToDeserializeCoseKey)?;

    // Extract key bytes and algorithm from the COSE key
    let kty = cose_key.kty;
    if !kty.eq("Symmetric") {
        Err(Error::InvalidKtyCoseKey(
            "kty must be Symmetric".to_string(),
        ))?;
    }

    let alg = cose_key.alg;
    let key_bytes = cose_key.key;

    match alg {
        alg if alg == Algorithm::HMAC_256_256.value() => {
            Hmac::<D>::new_from_slice(&key_bytes).map_err(Error::InvalidLengthCoseKey)
        }
        alg if alg == Algorithm::HMAC_384_384.value() => {
            Hmac::<D>::new_from_slice(&key_bytes).map_err(Error::InvalidLengthCoseKey)
        }
        alg if alg == Algorithm::HMAC_512_512.value() => {
            Hmac::<D>::new_from_slice(&key_bytes).map_err(Error::InvalidLengthCoseKey)
        }
        _ => Err(Error::InvalidAlgCoseKey(format!(
            "invalid algorithm: {}",
            alg
        )))?,
    }
}

/// Create a new `AES-CBC-MAC` instance from a COSE key. See [specs](https://datatracker.ietf.org/doc/html/rfc8152#section-9.2).
#[allow(dead_code)]
pub(crate) fn aes_cbc_mac_from_slice(cbor_key_bytes: &[u8]) -> Result<Aes256CbcMac>
where
    // C: BlockCipher + BlockEncryptMut + Clone,
{
    // Deserialize CBOR to CoseKey struct
    let cose_key: CoseKey =
        serde_cbor::from_slice(cbor_key_bytes).map_err(Error::UnableToDeserializeCoseKey)?;

    // Extract key bytes and algorithm from the COSE key
    let kty = cose_key.kty;
    if !kty.eq("Symmetric") {
        Err(Error::InvalidKtyCoseKey(
            "kty must be Symmetric".to_string(),
        ))?;
    }

    let alg = cose_key.alg;
    let key_bytes = cose_key.key;

    match alg {
        // alg if alg == Algorithm::AES_MAC_128_128.value() => {
        //     CbcMac::<Aes128>::new_from_slice(&key_bytes).map_err(Error::InvalidLengthCoseKey)
        // }
        alg if alg == Algorithm::AES_MAC_256_128.value() => {
            Aes256CbcMac::new_from_slice(&key_bytes).map_err(Error::InvalidLengthCoseKey)
        }
        _ => Err(Error::InvalidAlgCoseKey(format!(
            "invalid algorithm: {}",
            alg
        )))?,
    }
}

fn signature_payload(
    protected: &Protected,
    external_aad: Option<Vec<u8>>,
    payload: &[u8],
) -> std::result::Result<Vec<u8>, Error> {
    serde_cbor::to_vec(&vec![
        Value::Text("MAC0".into()),
        protected
            .clone()
            .try_into()
            .map_err(Error::UnableToSerializeProtected)?,
        Value::Bytes(external_aad.unwrap_or_default()),
        Value::Bytes(payload.to_vec()),
    ])
    .map_err(Error::UnableToSerializeSignaturePayload)
}

#[cfg(test)]
mod test {
    use hex::FromHex;
    use hmac::Hmac;

    use crate::cwt::{claim, NumericDate};

    use super::*;

    static COSE_MAC0_HMAC: &str = include_str!("../tests/mac0/serialized_hmac.cbor");
    static COSE_KEY_HMAC: &str = include_str!("../tests/mac0/secret_key_hmac");

    static COSE_MAC0_AES_CBC_MAC: &str = include_str!("../tests/mac0/serialized_aes_cbc_mac.cbor");
    static COSE_KEY_AES_CBC_MAC: &str = include_str!("../tests/mac0/secret_key_aes_cbc_mac");

    const RFC8392_KEY_HMAC: &str = "a361316953796d6d6574726963613305622d318f187418681869187318201869187318201874186818651820186b18651879";
    const RFC8392_COSE_MAC0_HMAC: &str = "d28443a10105a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71582043e0c95d0f37db3c29c841f73c61b6912ba7558ee228c35cf2afbca24c81119e";

    #[test]
    fn roundtrip_hmac() {
        let bytes = Vec::<u8>::from_hex(COSE_MAC0_HMAC).unwrap();
        let parsed: CoseMac0 =
            serde_cbor::from_slice(&bytes).expect("failed to parse COSE_MAC0 from bytes");
        let roundtripped =
            serde_cbor::to_vec(&parsed).expect("failed to serialize COSE_MAC0 to bytes");
        assert_eq!(
            bytes, roundtripped,
            "original bytes and roundtripped bytes do not match"
        );
    }

    #[test]
    fn roundtrip_aes_cbc_mac() {
        let bytes = Vec::<u8>::from_hex(COSE_MAC0_AES_CBC_MAC).unwrap();
        let parsed: CoseMac0 =
            serde_cbor::from_slice(&bytes).expect("failed to parse COSE_MAC0 from bytes");
        let roundtripped =
            serde_cbor::to_vec(&parsed).expect("failed to serialize COSE_MAC0 to bytes");
        assert_eq!(
            bytes, roundtripped,
            "original bytes and roundtripped bytes do not match"
        );
    }

    #[test]
    fn signing_hmac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_HMAC).unwrap();
        let signer: HmacSha256 = hmac_from_slice(&key).expect("HMAC can take key of any size");
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, Value::Bytes("11".into()));
        let cose_mac0 = CoseMac0::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .sign::<HmacSha256, Vec<u8>>(&signer)
            .unwrap();
        let serialized =
            serde_cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_MAC0_HMAC).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Mac0 and signed data do not match"
        );
    }

    #[test]
    fn signing_aes_cbc_mac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_AES_CBC_MAC).unwrap();
        let signer: Aes256CbcMac =
            aes_cbc_mac_from_slice(&key).expect("invalid key length for AES-256");
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, serde_cbor::Value::Bytes("11".into()));
        let cose_mac0 = CoseMac0::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .sign::<Aes256CbcMac, Vec<u8>>(&signer)
            .unwrap();
        let serialized =
            serde_cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_MAC0_AES_CBC_MAC).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Mac0 and signed data do not match"
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn signing_sync_hmac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_HMAC).unwrap();
        let signer: HmacSha256 = hmac_from_slice(&key).expect("HMAC can take key of any size");
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, serde_cbor::Value::Bytes("11".into()));
        let cose_mac0 = CoseMac0::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .sign_async::<HmacSha256, Vec<u8>>(&signer)
            .await
            .unwrap();
        let serialized =
            serde_cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_MAC0_HMAC).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Mac0 and signed data do not match"
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn signing_sync_aes_cbc_mac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_AES_CBC_MAC).unwrap();
        let signer: Aes256CbcMac =
            aes_cbc_mac_from_slice(&key).expect("invalid key length for AES-256");
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, serde_cbor::Value::Bytes("11".into()));
        let cose_mac0 = CoseMac0::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .sign_async::<Aes256CbcMac, Vec<u8>>(&signer)
            .await
            .unwrap();
        let serialized =
            serde_cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_MAC0_AES_CBC_MAC).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Mac0 and signed data do not match"
        );
    }

    #[test]
    fn verifying_hmac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_HMAC).unwrap();
        let verifier: HmacSha256 = hmac_from_slice(&key).expect("HMAC can take key of any size");

        let cose_mac0_bytes = Vec::<u8>::from_hex(COSE_MAC0_HMAC).unwrap();
        let cose_mac0: CoseMac0 =
            serde_cbor::from_slice(&cose_mac0_bytes).expect("failed to parse COSE_MAC0 from bytes");

        cose_mac0
            .verify::<HmacSha256, Vec<u8>>(&verifier, None, None)
            .to_result()
            .expect("COSE_MAC0 could not be verified")
    }

    #[test]
    fn verifying_aes_cbc_mac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_AES_CBC_MAC).unwrap();
        let verifier: Aes256CbcMac =
            aes_cbc_mac_from_slice(&key).expect("invalid key length for AES-256");

        let cose_mac0_bytes = Vec::<u8>::from_hex(COSE_MAC0_AES_CBC_MAC).unwrap();
        let cose_mac0: CoseMac0 =
            serde_cbor::from_slice(&cose_mac0_bytes).expect("failed to parse COSE_MAC0 from bytes");

        cose_mac0
            .verify::<Aes256CbcMac, Vec<u8>>(&verifier, None, None)
            .to_result()
            .expect("COSE_MAC0 could not be verified")
    }

    #[test]
    fn remote_signed_hmac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_HMAC).unwrap();
        let signer: HmacSha256 = hmac_from_slice(&key).expect("HMAC can take key of any size");
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, Value::Bytes("11".into()));
        let prepared = CoseMac0::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .signature_algorithm(Algorithm::HMAC_256_256)
            .prepare()
            .unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = signer.sign(signature_payload);
        let cose_mac0 = prepared.finalize(signature);
        let serialized =
            serde_cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_MAC0_HMAC).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Mac0 and signed data do not match"
        );

        let verifier: HmacSha256 = hmac_from_slice(&key).expect("HMAC can take key of any size");
        cose_mac0
            .verify::<HmacSha256, Vec<u8>>(&verifier, None, None)
            .to_result()
            .expect("COSE_MAC0 could not be verified")
    }

    #[test]
    fn remote_signed_aes_cbc_mac() {
        let key = Vec::<u8>::from_hex(COSE_KEY_AES_CBC_MAC).unwrap();
        let signer: Aes256CbcMac =
            aes_cbc_mac_from_slice(&key).expect("invalid key length for AES-256");
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, Value::Bytes("11".into()));
        let prepared = CoseMac0::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .signature_algorithm(Algorithm::AES_MAC_256_128)
            .prepare()
            .unwrap();
        let signature_payload = prepared.signature_payload();
        let signature = signer.sign(signature_payload);
        let cose_mac0 = prepared.finalize(signature);
        let serialized =
            serde_cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_MAC0_AES_CBC_MAC).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Mac0 and signed data do not match"
        );

        let verifier: Aes256CbcMac =
            aes_cbc_mac_from_slice(&key).expect("invalid key length for AES-256");
        cose_mac0
            .verify::<Aes256CbcMac, Vec<u8>>(&verifier, None, None)
            .to_result()
            .expect("COSE_MAC0 could not be verified")
    }

    fn rfc8392_example_inputs() -> (HeaderMap, HeaderMap, ClaimsSet) {
        let mut protected = HeaderMap::default();
        protected.insert_i(1, Value::Integer(Algorithm::HMAC_256_256.value() as i128));

        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(
            4, // kid
            Value::Bytes(
                hex::decode("4173796d6d65747269634543445341323536").expect("error decoding key id"),
            ),
        );

        let mut claims_set = ClaimsSet::default();
        claims_set
            .insert_claim(claim::Issuer::new("coap://as.example.com".into()))
            .expect("failed to insert issuer");
        claims_set
            .insert_claim(claim::Subject::new("erikw".into()))
            .expect("failed to insert subject");
        claims_set
            .insert_claim(claim::Audience::new("coap://light.example.com".into()))
            .expect("failed to insert audience");
        claims_set
            .insert_claim(claim::ExpirationTime::new(NumericDate::IntegerSeconds(
                1444064944,
            )))
            .expect("failed to insert expiration time");
        claims_set
            .insert_claim(claim::NotBefore::new(NumericDate::IntegerSeconds(
                1443944944,
            )))
            .expect("failed to insert not before");
        claims_set
            .insert_claim(claim::IssuedAt::new(NumericDate::IntegerSeconds(
                1443944944,
            )))
            .expect("failed to insert issued at");
        claims_set
            .insert_claim(claim::CWTId::new(hex::decode("0b71").unwrap()))
            .expect("failed to insert CWT ID");
        (protected, unprotected, claims_set)
    }

    #[test]
    fn signing_hmac_cwt() {
        // Using key from RFC8392 example
        let key = hex::decode(RFC8392_KEY_HMAC).unwrap();
        let signer: Hmac<Sha256> = hmac_from_slice(&key).expect("HMAC can take key of any size");
        let (protected, unprotected, claims_set) = rfc8392_example_inputs();
        let cose_mac0 = CoseMac0::builder()
            .protected(protected)
            .unprotected(unprotected)
            .claims_set(claims_set)
            .expect("failed to set claims set")
            .tagged()
            .sign::<HmacSha256, Vec<u8>>(&signer)
            .expect("failed to sign CWT");
        let serialized =
            serde_cbor::to_vec(&cose_mac0).expect("failed to serialize COSE_MAC0 to bytes");
        let expected = hex::decode(RFC8392_COSE_MAC0_HMAC).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Mac0 and signed CWT do not match"
        );
    }

    #[test]
    fn deserializing_signed_cwt() {
        let cose_mac0_bytes = hex::decode(RFC8392_COSE_MAC0_HMAC).unwrap();
        let cose_mac0: CoseMac0 =
            serde_cbor::from_slice(&cose_mac0_bytes).expect("failed to parse COSE_MAC0 from bytes");
        let parsed_claims_set = cose_mac0
            .claims_set()
            .expect("failed to parse claims set from payload")
            .expect("retrieved empty claims set");
        let (_, _, expected_claims_set) = rfc8392_example_inputs();
        assert_eq!(parsed_claims_set, expected_claims_set);
    }
}
