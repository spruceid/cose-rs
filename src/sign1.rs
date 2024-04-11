use crate::algorithm::{Algorithm, SignatureAlgorithm};
use crate::cwt::{self, ClaimsSet};
pub use crate::{header_map::HeaderMap, protected::Protected};
use serde::{
    de::{self, Error as DeError},
    ser, Deserialize, Serialize,
};
use serde_bytes::ByteBuf;
use serde_cbor::{tags::Tagged, Value};
use signature::{SignatureEncoding, Signer, Verifier};

/// COSE_Sign1 implementation.
#[derive(Clone, Debug)]
pub struct CoseSign1 {
    tagged: bool,
    inner: CoseSign1Inner,
}

/// Prepared COSE_Sign1 for remote signing.
///
/// To produce a COSE_Sign1 do the following:
///
/// 1. Set the signature algorithm in the builder using [`Builder::signature_algorithm`].
/// 2. Produce a signature remotely according to the chosen signature algorithm,
///    using the [`Self::signature_payload`] as the payload.
/// 3. Generate the COSE_Sign1 by passing the produced signature into
///    [`Self::finalize`].
///
/// Example:
/// ```ignore
/// let builder = builder.signature_algorithm(Algorithm::ES256);
/// let prepared: PreparedCoseSign1 = builder.prepare()?;
/// let signature_payload = prepared.signature_payload();
/// let signature = /* produce a signature according to ES256 using signature_payload as the payload */;
/// let cose_sign1: CoseSign1 = prepared.finalize(signature);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedCoseSign1 {
    tagged: bool,
    protected: Protected,
    unprotected: HeaderMap,
    payload: Option<ByteBuf>,
    signature_payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoseSign1Inner(Protected, HeaderMap, Option<ByteBuf>, ByteBuf);

/// Builder for COSE_Sign1.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    tagged: bool,
    detached: bool,
    protected: Protected,
    unprotected: HeaderMap,
    external_aad: Option<Vec<u8>>,
    payload: Option<ByteBuf>,
}

/// Errors that can occur when building, signing or verifying a COSE_Sign1.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the COSE_Sign1 has an attached payload but an detached payload was provided to the verify function")]
    DoublePayload,
    #[error("the COSE_Sign1 has a detached payload which was not provided to the verify function")]
    NoPayload,
    #[error("signature did not match the structure expected by the verifier: {0}")]
    MalformedSignature(signature::Error),
    #[error("error occurred when signing COSE_Sign1: {0}")]
    Signing(signature::Error),
    #[error("unable to serialize COSE_Sign1 protected headers: {0}")]
    UnableToSerializeProtected(serde_cbor::Error),
    #[error("unable to serialize COSE_Sign1 signature payload: {0}")]
    UnableToSerializeSignaturePayload(serde_cbor::Error),
    #[error("unable to set ClaimsSet: {0}")]
    UnableToDeserializeIntoClaimsSet(serde_cbor::Error),
}

/// Result with error type: [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Result for verification of a COSE_Sign1.
#[derive(Debug)]
pub enum VerificationResult {
    Success,
    Failure(String),
    Error(Error),
}

impl CoseSign1 {
    /// Construct a builder for a new COSE_Sign1.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Verify that the signature of a COSE_Sign1 is authentic.
    pub fn verify<'a, V, S>(
        &'a self,
        verifier: &V,
        detached_payload: Option<Vec<u8>>,
        external_aad: Option<Vec<u8>>,
    ) -> VerificationResult
    where
        V: Verifier<S> + SignatureAlgorithm,
        S: TryFrom<&'a [u8]>,
        S::Error: Into<signature::Error>,
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

        let signature = match S::try_from(self.inner.3.as_ref())
            .map_err(Into::into)
            .map_err(Error::MalformedSignature)
        {
            Ok(sig) => sig,
            Err(e) => return VerificationResult::Error(e),
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

impl ser::Serialize for CoseSign1 {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if self.tagged {
            Tagged::<&CoseSign1Inner>::new(Some(18), &self.inner)
        } else {
            Tagged::<&CoseSign1Inner>::new(None, &self.inner)
        }
        .serialize(s)
    }
}

impl<'de> de::Deserialize<'de> for CoseSign1 {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let cose_sign = Tagged::<CoseSign1Inner>::deserialize(d)?;
        let tagged = match cose_sign.tag {
            None => false,
            Some(18) => true,
            Some(n) => {
                return Err(D::Error::custom(format!(
                    "unable to deserialize CoseSign1: expected tag 18, received tag {}",
                    n
                )))
            }
        };
        Ok(Self {
            tagged,
            inner: cose_sign.value,
        })
    }
}

impl Builder {
    /// Set the tagged flag, so that the generated COSE_Sign1 is serialized with cbor tag 18.
    pub fn tagged(mut self) -> Self {
        self.tagged = true;
        self
    }

    /// Set the detached flag, so that the payload will not be included in the COSE_Sign1.
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
    /// COSE_Sign1 (RFC-8152#Section4.3).
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

    /// Set the CWT claims set.
    pub fn claims_set(self, claims_set: ClaimsSet) -> Result<Self, cwt::Error> {
        let serialized_claims = claims_set.serialize()?;
        Ok(self.payload(serialized_claims))
    }

    /// Set the signature algorithm in the protected headers.
    ///
    /// This is not required if signing directly as it can be derived from the signer,
    /// but should be set if using [`Self::prepare`] and producing the signature remotely.
    pub fn signature_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.protected.insert_i(1, algorithm.value().into());
        self
    }

    /// Prepare a CoseSign1 for remote signing.
    pub fn prepare(self) -> Result<PreparedCoseSign1> {
        let payload = self
            .payload
            // If payload is None, use cbor null as payload.
            .unwrap_or_else(|| ByteBuf::from([246u8]));
        let signature_payload =
            signature_payload(&self.protected, self.external_aad, payload.as_ref())?;
        let prepared = if self.detached {
            PreparedCoseSign1 {
                tagged: self.tagged,
                protected: self.protected,
                unprotected: self.unprotected,
                payload: None,
                signature_payload,
            }
        } else {
            PreparedCoseSign1 {
                tagged: self.tagged,
                protected: self.protected,
                unprotected: self.unprotected,
                payload: Some(payload),
                signature_payload,
            }
        };
        Ok(prepared)
    }

    /// Sign and generate the COSE_Sign1.
    pub fn sign<S, Sig>(mut self, s: &S) -> Result<CoseSign1>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
    {
        if self.protected.get_i(1).is_none() {
            self.protected.insert_i(1, s.algorithm().value().into());
        }
        let prepared = self.prepare()?;
        let signature_payload = prepared.signature_payload();
        let signature = s
            .try_sign(signature_payload)
            .map_err(Error::Signing)?
            .to_vec();
        Ok(prepared.finalize(signature))
    }

    /// Asynchronously sign and generate the COSE_Sign1.
    #[cfg(feature = "async")]
    pub async fn sign_async<S, Sig>(mut self, s: &S) -> Result<CoseSign1>
    where
        S: async_signature::AsyncSigner<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding + Send + 'static,
    {
        if self.protected.get_i(1).is_none() {
            self.protected.insert_i(1, s.algorithm().value().into());
        }
        let prepared = self.prepare()?;
        let signature_payload = prepared.signature_payload();
        let signature = s
            .sign_async(signature_payload)
            .await
            .map_err(Error::Signing)?
            .to_vec();
        Ok(prepared.finalize(signature))
    }
}

impl PreparedCoseSign1 {
    /// Retrieve the signature payload, i.e. the data that must be signed over.
    pub fn signature_payload(&self) -> &[u8] {
        self.signature_payload.as_slice()
    }

    /// Finalise the PreparedCoseSign1 with a remotely signed signature.
    pub fn finalize(self, signature: Vec<u8>) -> CoseSign1 {
        let inner = CoseSign1Inner(
            self.protected,
            self.unprotected,
            self.payload,
            ByteBuf::from(signature),
        );
        CoseSign1 {
            tagged: self.tagged,
            inner,
        }
    }
}

impl VerificationResult {
    /// Result of verification.
    ///
    /// False implies the signature is inauthentic or the verification algorithm encountered an
    /// error.
    pub fn success(&self) -> bool {
        matches!(self, VerificationResult::Success)
    }

    /// Translate to a std::result::Result.
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
    pub fn to_error(self) -> Option<Error> {
        match self {
            VerificationResult::Error(e) => Some(e),
            _ => None,
        }
    }
}

fn signature_payload(
    protected: &Protected,
    external_aad: Option<Vec<u8>>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    serde_cbor::to_vec(&vec![
        Value::Text("Signature1".into()),
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
    use super::*;
    use crate::cwt::{claim, NumericDate};

    use hex::FromHex;
    use p256::{
        ecdsa::{Signature, SigningKey, VerifyingKey},
        SecretKey,
    };

    static COSE_SIGN1: &str = include_str!("../tests/sign1/serialized.cbor");
    static COSE_KEY: &str = include_str!("../tests/sign1/secret_key");

    const RFC8392_KEY: &str = "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19";
    const RFC8392_COSE_SIGN1: &str = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30";

    #[test]
    fn roundtrip() {
        let bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let parsed: CoseSign1 =
            serde_cbor::from_slice(&bytes).expect("failed to parse COSE_Sign1 from bytes");
        let roundtripped =
            serde_cbor::to_vec(&parsed).expect("failed to serialize COSE_Sign1 to bytes");
        assert_eq!(
            bytes, roundtripped,
            "original bytes and roundtripped bytes do not match"
        );
    }

    #[test]
    fn signing() {
        let bytes = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&bytes).unwrap().into();
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, serde_cbor::Value::Bytes("11".into()));
        let cose_sign1 = CoseSign1::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .sign::<SigningKey, Signature>(&signer)
            .unwrap();
        let serialized =
            serde_cbor::to_vec(&cose_sign1).expect("failed to serialize COSE_Sign1 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Sign1 and signed data do not match"
        );
    }

    #[test]
    fn verifying() {
        let bytes = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&bytes).unwrap().into();
        let verifier: VerifyingKey = (&signer).into();

        let cose_sign1_bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let cose_sign1: CoseSign1 = serde_cbor::from_slice(&cose_sign1_bytes)
            .expect("failed to parse COSE_Sign1 from bytes");

        cose_sign1
            .verify::<VerifyingKey, Signature>(&verifier, None, None)
            .to_result()
            .expect("COSE_Sign1 could not be verified")
    }

    #[test]
    fn remote_signed() {
        let bytes = Vec::<u8>::from_hex(COSE_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&bytes).unwrap().into();
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, serde_cbor::Value::Bytes("11".into()));
        let prepared = CoseSign1::builder()
            .protected(HeaderMap::default())
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .signature_algorithm(Algorithm::ES256)
            .prepare()
            .unwrap();
        let signature: Signature = signer.sign(prepared.signature_payload());
        let cose_sign1 = prepared.finalize(signature.to_vec());
        let serialized =
            serde_cbor::to_vec(&cose_sign1).expect("failed to serialize COSE_Sign1 to bytes");

        let expected = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Sign1 and signed data do not match"
        );

        let verifier: VerifyingKey = (&signer).into();
        cose_sign1
            .verify::<VerifyingKey, Signature>(&verifier, None, None)
            .to_result()
            .expect("COSE_Sign1 could not be verified")
    }

    fn rfc8392_example_inputs() -> (HeaderMap, HeaderMap, ClaimsSet) {
        let mut protected = HeaderMap::default();
        protected.insert_i(1, serde_cbor::Value::Integer(-7));

        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(
            4, // kid
            serde_cbor::Value::Bytes(
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
    fn signing_cwt() {
        // Using key from RFC8392 example
        let bytes = hex::decode(RFC8392_KEY).unwrap();
        let signer: SigningKey = SecretKey::from_slice(&bytes).unwrap().into();
        let (protected, unprotected, claims_set) = rfc8392_example_inputs();
        let cose_sign1 = CoseSign1::builder()
            .protected(protected)
            .unprotected(unprotected)
            .claims_set(claims_set)
            .expect("failed to set claims set")
            .tagged()
            .sign::<SigningKey, Signature>(&signer)
            .expect("failed to sign CWT");
        let serialized =
            serde_cbor::to_vec(&cose_sign1).expect("failed to serialize COSE_Sign1 to bytes");
        let expected = hex::decode(RFC8392_COSE_SIGN1).unwrap();
        assert_eq!(
            expected, serialized,
            "expected COSE_Sign1 and signed CWT do not match"
        );
    }

    #[test]
    fn deserializing_signed_cwt() {
        let cose_sign1_bytes = hex::decode(RFC8392_COSE_SIGN1).unwrap();
        let cose_sign1: CoseSign1 = serde_cbor::from_slice(&cose_sign1_bytes)
            .expect("failed to parse COSE_Sign1 from bytes");
        let parsed_claims_set = cose_sign1
            .claims_set()
            .expect("failed to parse claims set from payload")
            .expect("retrieved empty claims set");
        let (_, _, expected_claims_set) = rfc8392_example_inputs();
        assert_eq!(parsed_claims_set, expected_claims_set);
    }
}
