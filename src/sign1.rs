use crate::{header_map::HeaderMap, protected::Protected};
use serde::{
    de::{self, Error as DeError},
    ser, Deserialize, Serialize,
};
use serde_bytes::ByteBuf;
use serde_cbor::{tags::Tagged, Value};
use signature::{Signature, Signer, Verifier};

#[derive(Clone, Debug)]
pub struct CoseSign1 {
    tagged: bool,
    inner: CoseSign1Inner,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoseSign1Inner(Protected, HeaderMap, Option<ByteBuf>, ByteBuf);

#[derive(Clone, Debug, Default)]
pub struct Builder {
    tagged: bool,
    detached: bool,
    protected: Protected,
    unprotected: HeaderMap,
    external_aad: Option<Vec<u8>>,
    payload: Option<ByteBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the COSE_Sign1 has an attached payload but an detached payload was provided to the verify function")]
    DoublePayload,
    #[error("the COSE_Sign1 has a detached payload which was not provided to the verify function")]
    NoPayload,
    #[error("signature is not authentic: {0}")]
    FailedVerification(signature::Error),
    #[error("signature did not match the structure expected by the verifier: {0}")]
    MalformedSignature(signature::Error),
    #[error("error occurred when signing COSE_Sign1: {0}")]
    Signing(signature::Error),
    #[error("unable to serialize COSE_Sign1 protected headers: {0}")]
    UnableToSerializeProtected(serde_cbor::Error),
    #[error("unable to serialize COSE_Sign1 signature structure: {0}")]
    UnableToSerializeSigStructure(serde_cbor::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl CoseSign1 {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn verify<V, S>(
        &self,
        verifier: &V,
        detached_payload: Option<Vec<u8>>,
        external_aad: Option<Vec<u8>>,
    ) -> Result<()>
    where
        V: Verifier<S>,
        S: Signature,
    {
        let payload = match (self.inner.2.as_ref(), detached_payload.as_ref()) {
            (None, None) => return Err(Error::NoPayload),
            (Some(attached), None) => attached,
            (None, Some(detached)) => detached,
            _ => return Err(Error::DoublePayload),
        };
        let signature = S::from_bytes(self.inner.3.as_ref()).map_err(Error::MalformedSignature)?;
        let to_be_verified = to_be_signed(&self.inner.0, external_aad, payload)?;
        verifier
            .verify(&to_be_verified, &signature)
            .map_err(Error::FailedVerification)
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
    pub fn tagged(mut self) -> Self {
        self.tagged = true;
        self
    }

    pub fn detached(mut self) -> Self {
        self.detached = true;
        self
    }

    pub fn protected<P>(mut self, protected: P) -> Self
    where
        P: Into<Protected>,
    {
        self.protected = protected.into();
        self
    }

    pub fn unprotected<H>(mut self, unprotected: H) -> Self
    where
        H: Into<HeaderMap>,
    {
        self.unprotected = unprotected.into();
        self
    }

    pub fn external_aad<B>(mut self, external_aad: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        self.external_aad = Some(external_aad.into());
        self
    }

    pub fn payload<P>(mut self, p: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        self.payload = Some(ByteBuf::from(p));
        self
    }

    pub fn sign<S, Sig>(self, s: &S) -> Result<CoseSign1>
    where
        S: Signer<Sig>,
        Sig: Signature,
    {
        let payload = self
            .payload
            // If payload is None, use cbor null as payload.
            .unwrap_or_else(|| ByteBuf::from([246u8]));
        let to_be_signed = to_be_signed(&self.protected, self.external_aad, payload.as_ref())?;
        let signature = s
            .try_sign(&to_be_signed)
            .map_err(Error::Signing)?
            .as_bytes()
            .to_vec();
        let inner = if self.detached {
            CoseSign1Inner(
                self.protected,
                self.unprotected,
                None,
                ByteBuf::from(signature),
            )
        } else {
            CoseSign1Inner(
                self.protected,
                self.unprotected,
                Some(payload),
                ByteBuf::from(signature),
            )
        };
        Ok(CoseSign1 {
            tagged: self.tagged,
            inner,
        })
    }

    #[cfg(feature = "async")]
    pub async fn async_sign<S, Sig>(self, s: &S) -> Result<CoseSign1>
    where
        S: async_signature::AsyncSigner<Sig>,
        Sig: Signature + Send + 'static,
    {
        let payload = self
            .payload
            // If payload is None, use cbor null as payload.
            .unwrap_or_else(|| ByteBuf::from([246u8]));
        let to_be_signed = to_be_signed(&self.protected, self.external_aad, payload.as_ref())?;
        let signature = s
            .sign_async(&to_be_signed)
            .await
            .map_err(Error::Signing)?
            .as_bytes()
            .to_vec();
        let inner = if self.detached {
            CoseSign1Inner(
                self.protected,
                self.unprotected,
                None,
                ByteBuf::from(signature),
            )
        } else {
            CoseSign1Inner(
                self.protected,
                self.unprotected,
                Some(payload),
                ByteBuf::from(signature),
            )
        };
        Ok(CoseSign1 {
            tagged: self.tagged,
            inner,
        })
    }
}

fn to_be_signed(
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
    .map_err(Error::UnableToSerializeSigStructure)
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;
    use p256::{
        ecdsa::{SigningKey, VerifyingKey},
        SecretKey,
    };

    static COSE_SIGN1: &str = include_str!("../tests/sign1/serialized.cbor");
    static COSE_KEY: &str = include_str!("../tests/sign1/secret_key");

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
        let signer: SigningKey = SecretKey::from_be_bytes(&bytes).unwrap().into();
        let mut protected = HeaderMap::default();
        protected.insert_i(1, (-7).into());
        let mut unprotected = HeaderMap::default();
        unprotected.insert_i(4, serde_cbor::Value::Bytes("11".into()));
        let cose_sign1 = CoseSign1::builder()
            .protected(protected)
            .unprotected(unprotected)
            .payload("This is the content.")
            .tagged()
            .sign(&signer)
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
        let signer: SigningKey = SecretKey::from_be_bytes(&bytes).unwrap().into();
        let verifier: VerifyingKey = (&signer).into();

        let cose_sign1_bytes = Vec::<u8>::from_hex(COSE_SIGN1).unwrap();
        let cose_sign1: CoseSign1 = serde_cbor::from_slice(&cose_sign1_bytes)
            .expect("failed to parse COSE_Sign1 from bytes");

        cose_sign1
            .verify(&verifier, None, None)
            .expect("COSE_Sign1 could not be verified")
    }
}
