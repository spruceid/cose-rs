// TODO EN: consider whether to name this claims_set or cwt?
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::ops::Deref;

pub use crate::claim::Claim;

/// CWT claims set.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimsSet(BTreeMap<Value, Value>);

impl ClaimsSet {
    /// Insert a claim with an integer label.
    pub fn insert_i<L: Into<i128>>(&mut self, label: L, value: Value) -> Option<Value> {
        let i: i128 = label.into();
        // TODO EN: potentially add restrictions based on registered claims
        self.0.insert(Value::Integer(i), value)
    }

    pub fn insert_claim(&mut self, claim: Claim) -> Option<Value> {
        self.insert_i(claim.key(), claim.value())
    }

    /// Insert a claim with a text label.
    pub fn insert_t<L: Into<String>>(&mut self, label: L, value: Value) -> Option<Value> {
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
        claims_set.insert_claim(Claim::Issuer("coap://as.example.com"));
        claims_set.insert_claim(Claim::Subject("erikw"));
        claims_set.insert_claim(Claim::Audience("coap://light.example.com"));
        claims_set.insert_claim(Claim::ExpirationTime(1444064944));
        claims_set.insert_claim(Claim::NotBefore(1443944944));
        claims_set.insert_claim(Claim::IssuedAt(1443944944));
        claims_set.insert_claim(Claim::CWTId(hex::decode("0b71").unwrap()));

        let serialized = claims_set
            .serialize()
            .expect("failed to serialize claims set");
        let expected = hex::decode("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71").unwrap();
        assert_eq!(serialized, expected);
    }
}
