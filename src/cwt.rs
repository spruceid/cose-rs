use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::ops::Deref;

pub use crate::claim::{self, Claim, Key, NumericDate};

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

    fn test_cases() -> Vec<(&'static str, ClaimsSet, Vec<u8>)> {
        // Checked against coset
        let serialized1 = hex::decode("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb005fb41d584367c200000060007420b71").unwrap();
        let mut claims_set1 = ClaimsSet::default();
        // Basic test case tweaks RFC8392 example to include fractional & "0" dates
        claims_set1.insert_claim(claim::Issuer("coap://as.example.com".into()));
        claims_set1.insert_claim(claim::Subject("erikw".into()));
        claims_set1.insert_claim(claim::Audience("coap://light.example.com".into()));
        claims_set1.insert_claim(claim::ExpirationTime(NumericDate::Integer(1444064944)));
        claims_set1.insert_claim(claim::NotBefore(NumericDate::Fractional(1443944944.5)));
        claims_set1.insert_claim(claim::IssuedAt(NumericDate::Integer(0)));
        claims_set1.insert_claim(claim::CWTId(hex::decode("0b71").unwrap()));

        // Reordered case above
        let mut claims_set2 = ClaimsSet::default();
        claims_set2.insert_claim(claim::IssuedAt(NumericDate::Integer(0)));
        claims_set2.insert_claim(claim::Subject("erikw".into()));
        claims_set2.insert_claim(claim::NotBefore(NumericDate::Fractional(1443944944.5)));
        claims_set2.insert_claim(claim::CWTId(hex::decode("0b71").unwrap()));
        claims_set2.insert_claim(claim::ExpirationTime(NumericDate::Integer(1444064944)));
        claims_set2.insert_claim(claim::Audience("coap://light.example.com".into()));
        claims_set2.insert_claim(claim::Issuer("coap://as.example.com".into()));

        vec![
            ("empty", ClaimsSet::default(), hex::decode("a0").unwrap()),
            ("normal", claims_set1, serialized1.clone()),
            ("reordered", claims_set2, serialized1),
        ]
    }

    #[test]
    fn serialize() {
        for (case, claims_set, expected_serialized) in test_cases() {
            let serialized = claims_set
                .serialize()
                .unwrap_or_else(|_| panic!("failed to serialize claims set for {}", case));
            assert_eq!(serialized, expected_serialized, "case: {}", case);
        }
    }

    #[test]
    fn deserialize() {
        for (case, expected_claims_set, serialized) in test_cases() {
            let parsed_claims_set: ClaimsSet = serde_cbor::from_slice(&serialized)
                .unwrap_or_else(|_| panic!("failed to deserialize bytes into claims set {}", case));
            assert_eq!(parsed_claims_set, expected_claims_set, "case: {}", case);
        }
    }
}
