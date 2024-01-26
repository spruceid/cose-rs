// TODO EN: consider whether to name this claims_set or cwt?
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::ops::Deref;

pub enum IANAClaim {
    Issuer(&'static str),
    Subject(&'static str),
    Audience(&'static str),
    ExpirationTime(i128), // TODO EN: these should technically also allow for fractional time...
    NotBefore(i128),
    IssuedAt(i128),
    CWTId(Vec<u8>),
}

impl IANAClaim {
    pub fn key(&self) -> i128 {
        match self {
            IANAClaim::Issuer(_) => 1,
            IANAClaim::Subject(_) => 2,
            IANAClaim::Audience(_) => 3,
            IANAClaim::ExpirationTime(_) => 4,
            IANAClaim::NotBefore(_) => 5,
            IANAClaim::IssuedAt(_) => 6,
            IANAClaim::CWTId(_) => 7,
        }
    }

    pub fn value(&self) -> Value {
        match self {
            IANAClaim::Issuer(value) => Value::Text(value.to_string()),
            IANAClaim::Subject(value) => Value::Text(value.to_string()),
            IANAClaim::Audience(value) => Value::Text(value.to_string()),
            IANAClaim::ExpirationTime(value) => Value::Integer(*value), // TODO EN: these should technically also allow for fractional time...
            IANAClaim::NotBefore(value) => Value::Integer(*value),
            IANAClaim::IssuedAt(value) => Value::Integer(*value),
            IANAClaim::CWTId(value) => Value::Bytes(value.to_vec()),
        }
    }
}

/// CWT claims set.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimsSet(BTreeMap<Value, Value>);

impl ClaimsSet {
    /// Insert a claim with an integer label.
    pub fn insert_i<L: Into<i128>>(&mut self, label: L, value: Value) -> Option<Value> {
        let i: i128 = label.into();
        // TODO EN: add number checks/restrictions
        self.0.insert(Value::Integer(i), value)
    }

    pub fn insert_claim(&mut self, claim: IANAClaim) -> Option<Value> {
        self.insert_i(claim.key(), claim.value())
    }

    /// Insert a claim with a text label.
    pub fn insert_t<L: Into<String>>(&mut self, label: L, value: Value) -> Option<Value> {
        // TODO EN: add any text restrictions
        self.0.insert(Value::Text(label.into()), value)
    }

    /// Retrieve a claim value with an integer label.
    pub fn get_i<L: Into<i128>>(&self, label: L) -> Option<&Value> {
        self.0.get(&Value::Integer(label.into()))
    }

    /// Retrieve a claim value with a text label.
    pub fn get_t<L: Into<String>>(&self, label: L) -> Option<&Value> {
        self.0.get(&Value::Text(label.into()))
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

// TODO EN: re-evaluate if this is necessary
impl From<BTreeMap<Value, Value>> for ClaimsSet {
    fn from(m: BTreeMap<Value, Value>) -> Self {
        Self(m)
    }
}

// impl From<ClaimsSet> for Vec<u8> {
//     fn from(h: ClaimsSet) -> Self {
//         // TODO EN: From trait cannot fail so unwrap is probably not what we want here
//         serde_cbor::to_vec(&h).unwrap()
//     }
// }

// An alternative could be something like:
// 1. Requiring a call to "serialize" or something like that first,
// then after that making it possible to convert from a new type Into Vec<u8>?
// Or just leave From unimplemented for utf-8, provide `serialize` helper
// and then require caller to explicitly call that + handle return type/error?

// impl TryFrom<ClaimsSet> for Vec<u8> {
//     type Error = serde_cbor::Error;

//     fn try_from(h: ClaimsSet) -> Result<Vec<u8>, serde_cbor::Error> {
//         // TODO EN: From trait cannot fail so unwrap is probably not what we want here
//         serde_cbor::to_vec(&h)
//     }
// }

// TODO EN: probably needs to implement the From trait for adding to payload to work properly

// TODO EN: create a test for creating the serialized payload (or whatever gets added to the message)

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_payload() {
        // Example from RFC8392
        let mut claims_set = ClaimsSet::default();
        claims_set.insert_claim(IANAClaim::Issuer("coap://as.example.com"));
        claims_set.insert_claim(IANAClaim::Subject("erikw"));
        claims_set.insert_claim(IANAClaim::Audience("coap://light.example.com"));
        claims_set.insert_claim(IANAClaim::ExpirationTime(1444064944));
        claims_set.insert_claim(IANAClaim::NotBefore(1443944944));
        claims_set.insert_claim(IANAClaim::IssuedAt(1443944944));
        claims_set.insert_claim(IANAClaim::CWTId(hex::decode("0b71").unwrap()));

        let serialized = claims_set
            .serialize()
            .expect("failed to serialize claims set");
        let expected = hex::decode("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71").unwrap();
        assert_eq!(serialized, expected);
    }
}
