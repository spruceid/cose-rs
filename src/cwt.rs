use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::ops::Deref;

pub use crate::claim::{self, Claim, Key};

/// CWT claims set.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimsSet(BTreeMap<Value, Value>);

impl ClaimsSet {
    pub fn insert_claim<T: Claim>(&mut self, claim: T) -> Option<Value> {
        self.0.insert(T::key().into(), claim.into())
    }

    pub fn get_claim<T: Claim>(&self) -> Option<&Value> {
        self.0.get(&T::key().into())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(&self)
    }
}

impl AsRef<BTreeMap<Value, Value>> for ClaimsSet {
    fn as_ref(&self) -> &BTreeMap<Value, Value> {
        &self.0
    }
}

impl Deref for ClaimsSet {
    type Target = BTreeMap<Value, Value>;

    fn deref(&self) -> &BTreeMap<Value, Value> {
        &self.0
    }
}

impl From<BTreeMap<Value, Value>> for ClaimsSet {
    fn from(m: BTreeMap<Value, Value>) -> Self {
        Self(m)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_payload() {
        // Example from RFC8392
        let mut claims_set = ClaimsSet::default();
        claims_set.insert_claim(claim::Issuer("coap://as.example.com".into()));
        claims_set.insert_claim(claim::Subject("erikw".into()));
        claims_set.insert_claim(claim::Audience("coap://light.example.com".into()));
        claims_set.insert_claim(claim::ExpirationTime(1444064944));
        claims_set.insert_claim(claim::NotBefore(1443944944));
        claims_set.insert_claim(claim::IssuedAt(1443944944));
        claims_set.insert_claim(claim::CWTId(hex::decode("0b71").unwrap()));

        let serialized = claims_set
            .serialize()
            .expect("failed to serialize claims set");
        let expected = hex::decode("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71").unwrap();
        assert_eq!(serialized, expected);
    }
}
