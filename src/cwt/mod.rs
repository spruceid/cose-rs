pub mod claim;

use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;

pub use crate::cwt::claim::{Claim, Key, NumericDate};

#[cfg(feature = "numericdate-conversion")]
pub mod numericdate_conversion;

/// Representation of a CWT claims set (a CBOR map containing CWT claims),
/// as defined in [RFC8392](https://datatracker.ietf.org/doc/html/rfc8392).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimsSet(BTreeMap<Value, Value>);

impl ClaimsSet {
    /// Insert a defined CWT claim struct.
    /// Returns an error if the previous value found cannot be parsed
    /// into the expected claim structure.
    pub fn insert_claim<T: Claim>(&mut self, claim: T) -> Result<Option<T>, Error> {
        match self.0.insert(T::key().into(), claim.into()) {
            None => Ok(None),
            Some(v) => v.try_into().map_or_else(
                |e| Err(Error::UnableToParseClaim(e)),
                |claim| Ok(Some(claim)),
            ),
        }
    }

    /// Insert a claim with an integer key.
    pub fn insert_i<T: Into<i128>>(&mut self, key: T, value: Value) -> Option<Value> {
        self.0.insert(Value::Integer(key.into()), value)
    }

    /// Insert a claim with a text key.
    pub fn insert_t<T: Into<String>>(&mut self, key: T, value: Value) -> Option<Value> {
        self.0.insert(Value::Text(key.into()), value)
    }

    /// Retrieve a defined CWT claim struct.
    /// Returns an error if claim key is found but value cannot be parsed
    /// into expected claim structure.
    /// N.B. This method clones the underlying data.
    pub fn get_claim<T: Claim>(&self) -> Result<Option<T>, Error> {
        match self.0.get(&T::key().into()) {
            None => Ok(None),
            Some(v) => v.clone().try_into().map_or_else(
                |e| Err(Error::UnableToParseClaim(e)),
                |claim| Ok(Some(claim)),
            ),
        }
    }

    /// Retrieve a claim value with an integer key.
    pub fn get_i<T: Into<i128>>(&self, key: T) -> Option<&Value> {
        self.0.get(&Value::Integer(key.into()))
    }

    /// Retrieve a claim value with a text key.
    pub fn get_t<T: Into<String>>(&self, key: T) -> Option<&Value> {
        self.0.get(&Value::Text(key.into()))
    }

    /// Remove a defined CWT claim struct from ClaimsSet.
    /// Returns an error if the removed value cannot be parsed into
    /// the expected claim structure.
    pub fn remove_claim<T: Claim>(&mut self) -> Result<Option<T>, Error> {
        match self.0.remove(&T::key().into()) {
            None => Ok(None),
            Some(v) => v.try_into().map_or_else(
                |e| Err(Error::UnableToParseClaim(e)),
                |claim| Ok(Some(claim)),
            ),
        }
    }

    /// Remove a claim value with an integer key from ClaimsSet.
    pub fn remove_i<T: Into<i128>>(&mut self, key: T) -> Option<Value> {
        self.0.remove(&Value::Integer(key.into()))
    }

    /// Remove a claim value with a text key from ClaimsSet.
    pub fn remove_t<T: Into<String>>(&mut self, key: T) -> Option<Value> {
        self.0.remove(&Value::Text(key.into()))
    }

    /// Serialize the ClaimsSet to CBOR bytes, so that it
    /// can be attached as a payload to a COSE object.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        serde_cbor::to_vec(&self).map_err(Error::UnableToSerializeClaimsSet)
    }
}

/// Errors that can occur working with a ClaimsSet.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to serialize CWT ClaimsSet: {0}")]
    UnableToSerializeClaimsSet(serde_cbor::Error),
    #[error("unable to parse value into claim: {0}")]
    UnableToParseClaim(claim::Error),
    #[error("found invalid CWT Key: ${0}")]
    InvalidCwtKey(String),
}

impl TryFrom<BTreeMap<Value, Value>> for ClaimsSet {
    type Error = Error;

    fn try_from(m: BTreeMap<Value, Value>) -> Result<Self, Self::Error> {
        // Ensure keys are valid
        let mut claims_set = ClaimsSet::default();

        for (k, v) in m.iter() {
            match k {
                Value::Text(s) => claims_set.insert_t(s.clone(), v.clone()),
                Value::Integer(i) => claims_set.insert_i(*i, v.clone()),
                invalid_key_type => {
                    return Err(Error::InvalidCwtKey(format!("{:?}", invalid_key_type)))
                }
            };
        }
        Ok(claims_set)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use claim::Claim;

    fn test_cases() -> Vec<(&'static str, ClaimsSet, Vec<u8>)> {
        // Checked against coset
        let serialized1 = hex::decode("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb005fb41d584367c200000060007420b71").unwrap();
        let mut claims_set1 = ClaimsSet::default();
        // Basic test case tweaks RFC8392 example to include fractional & "0" dates
        claims_set1
            .insert_claim(claim::Issuer::new("coap://as.example.com".into()))
            .expect("claims_set1: failed to insert issuer");
        claims_set1
            .insert_claim(claim::Subject::new("erikw".into()))
            .expect("claims_set1: failed to insert subject");
        claims_set1
            .insert_claim(claim::Audience::new("coap://light.example.com".into()))
            .expect("claims_set1: failed to insert audience");
        claims_set1
            .insert_claim(claim::ExpirationTime::new(NumericDate::IntegerSeconds(
                1444064944,
            )))
            .expect("claims_set1: failed to insert expiration time");
        claims_set1
            .insert_claim(claim::NotBefore::new(NumericDate::FractionalSeconds(
                1443944944.5,
            )))
            .expect("claims_set1: failed to insert not before");
        claims_set1
            .insert_claim(claim::IssuedAt::new(NumericDate::IntegerSeconds(0)))
            .expect("claims_set1: failed to insert issued at");
        claims_set1
            .insert_claim(claim::CWTId::new(hex::decode("0b71").unwrap()))
            .expect("claims_set1: failed to insert CWT ID");

        // Reordered case above
        let mut claims_set2 = ClaimsSet::default();
        claims_set2
            .insert_claim(claim::IssuedAt::new(NumericDate::IntegerSeconds(0)))
            .expect("claims_set2: failed to insert issuer (with date value)");
        claims_set2
            .insert_claim(claim::Subject::new("erikw".into()))
            .expect("claims_set2: failed to insert subject");
        claims_set2
            .insert_claim(claim::NotBefore::new(NumericDate::FractionalSeconds(
                1443944944.5,
            )))
            .expect("claims_set2: failed to insert not before");
        claims_set2
            .insert_claim(claim::CWTId::new(hex::decode("0b71").unwrap()))
            .expect("claims_set2: failed to insert CWT ID");
        claims_set2
            .insert_claim(claim::ExpirationTime::new(NumericDate::IntegerSeconds(
                1444064944,
            )))
            .expect("claims_set2: failed to insert expiration time");
        claims_set2
            .insert_claim(claim::Audience::new("coap://light.example.com".into()))
            .expect("claims_set2: failed to insert audience");
        claims_set2
            .insert_claim(claim::Issuer::new("coap://as.example.com".into()))
            .expect("claims_set2: failed to insert issuer");

        let serialized3 =
            hex::decode("a23a000f423ffbc059161e4f765fd967746573746b6579393038").unwrap();

        let claims_set3: ClaimsSet = BTreeMap::from([
            (Value::Text("testkey".into()), Value::Integer(-12345)),
            (Value::Integer(-1000000), Value::Float(-100.3456)),
        ])
        .try_into()
        .expect("converting from BTreeMap failed");

        // Add and remove keys to ensure this doesn't change serialization
        let mut claims_set4 = claims_set1.clone();
        claims_set4.insert_t("testkey", Value::Integer(-12345));
        claims_set4.insert_i(-1000000, Value::Float(-100.3456));
        claims_set4.remove_t("testkey");
        claims_set4.remove_i(-1000000);

        vec![
            ("empty", ClaimsSet::default(), hex::decode("a0").unwrap()),
            ("normal", claims_set1, serialized1.clone()),
            ("reordered", claims_set2, serialized1.clone()),
            ("custom", claims_set3, serialized3),
            ("with_remove", claims_set4, serialized1),
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

    fn test_get_claim<T: Claim + Clone + PartialEq + std::fmt::Debug>(claim: T, case_name: &str) {
        let mut claims_set = ClaimsSet::default();
        claims_set
            .insert_claim(claim.clone())
            .unwrap_or_else(|_| panic!("{}: failed to insert claim", case_name));
        assert_eq!(
            claims_set
                .get_claim::<T>()
                .unwrap_or_else(|_| panic!("{}: failed to parse claim", case_name))
                .unwrap_or_else(|| panic!("{}: couldn't find claim", case_name)),
            claim
        );
    }

    #[test]
    fn get_claim() {
        // Ensure that we can get a structured claim of each data type
        let issuer = claim::Issuer::new("test text".into());
        let exp = claim::ExpirationTime::new(NumericDate::IntegerSeconds(1444064944));
        let cwt_id = claim::CWTId::new(hex::decode("0b71").unwrap());

        test_get_claim(issuer, "issuer (String value)");
        test_get_claim(exp, "expiration time (NumericDate value)");
        test_get_claim(cwt_id, "CWT ID (Bytes value)");
    }

    #[test]
    fn cannot_get_incorrectly_structured_claim() {
        // Manually construct issuer claim with integer value
        let mut claims_set = ClaimsSet::default();
        let Key::Integer(n) = claim::Issuer::key() else {
            panic!("non-int key for issuer found")
        };
        claims_set.insert_i(n, Value::Float(123.45));
        claims_set
            .get_claim::<claim::Issuer>()
            .expect_err("should have failed to parse claim");
    }
}
