use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;

pub use crate::claim::{self, Claim, Label, NumericDate};

/// CWT claims set.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimsSet(BTreeMap<Value, Value>);

impl ClaimsSet {
    pub fn insert_claim<T: Claim>(&mut self, claim: T) -> Option<Value> {
        self.0.insert(T::label().into(), claim.into())
    }

    pub fn get_claim<T: Claim>(&self) -> Option<&Value> {
        self.0.get(&T::label().into())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        serde_cbor::to_vec(&self).map_err(Error::UnableToSerializeClaimsSet)
    }
}

/// Errors that can occur working with a ClaimsSet.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to serialize CWT ClaimsSet: {0}")]
    UnableToSerializeClaimsSet(serde_cbor::Error),
}

#[cfg(test)]
mod test {
    use crate::define_claim;

    use super::*;

    fn test_cases() -> Vec<(&'static str, ClaimsSet, Vec<u8>)> {
        // Checked against coset
        let serialized1 = hex::decode("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb005fb41d584367c200000060007420b71").unwrap();
        let mut claims_set1 = ClaimsSet::default();
        // Basic test case tweaks RFC8392 example to include fractional & "0" dates
        claims_set1.insert_claim(claim::Issuer::new("coap://as.example.com".into()));
        claims_set1.insert_claim(claim::Subject::new("erikw".into()));
        claims_set1.insert_claim(claim::Audience::new("coap://light.example.com".into()));
        claims_set1.insert_claim(claim::ExpirationTime::new(NumericDate::Integer(1444064944)));
        claims_set1.insert_claim(claim::NotBefore::new(NumericDate::Fractional(1443944944.5)));
        claims_set1.insert_claim(claim::IssuedAt::new(NumericDate::Integer(0)));
        claims_set1.insert_claim(claim::CWTId::new(hex::decode("0b71").unwrap()));

        // Reordered case above
        let mut claims_set2 = ClaimsSet::default();
        claims_set2.insert_claim(claim::IssuedAt::new(NumericDate::Integer(0)));
        claims_set2.insert_claim(claim::Subject::new("erikw".into()));
        claims_set2.insert_claim(claim::NotBefore::new(NumericDate::Fractional(1443944944.5)));
        claims_set2.insert_claim(claim::CWTId::new(hex::decode("0b71").unwrap()));
        claims_set2.insert_claim(claim::ExpirationTime::new(NumericDate::Integer(1444064944)));
        claims_set2.insert_claim(claim::Audience::new("coap://light.example.com".into()));
        claims_set2.insert_claim(claim::Issuer::new("coap://as.example.com".into()));

        // Create some dummy claims using negative/text labels
        define_claim!(
            TestStringLabel,
            serde_cbor::Value,
            Label::Text("testlabel".into())
        );
        define_claim!(TestNegIntLabel, serde_cbor::Value, Label::Integer(-1000000));

        let serialized3 =
            hex::decode("a23a000f423ffbc059161e4f765fd969746573746c6162656c393038").unwrap();

        let mut claims_set3 = ClaimsSet::default();
        claims_set3.insert_claim(TestStringLabel(Value::Integer(-12345)));
        claims_set3.insert_claim(TestNegIntLabel(Value::Float(-100.3456)));

        vec![
            ("empty", ClaimsSet::default(), hex::decode("a0").unwrap()),
            ("normal", claims_set1, serialized1.clone()),
            ("reordered", claims_set2, serialized1),
            ("custom", claims_set3, serialized3),
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

    #[test]
    fn roundtrip() {
        for (case, claims_set, _) in test_cases() {
            let serialized = claims_set
                .serialize()
                .unwrap_or_else(|_| panic!("failed to serialize claims set for {}", case));
            let parsed_claims: ClaimsSet = serde_cbor::from_slice(&serialized)
                .unwrap_or_else(|_| panic!("failed to deserialize bytes into claims set {}", case));
            assert_eq!(parsed_claims, claims_set, "case: {}", case);
        }
    }
}
