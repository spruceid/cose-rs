//! Standard COSE headers for convenience, as specified in the
//! [COSE Header Parameters registry](https://www.iana.org/assignments/cose/cose.xhtml).
use super::Header;
pub use crate::cwt::claim::Key;
use serde::{de::Error as _, Deserialize, Serialize};
use serde_cbor::Value;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[serde(untagged)]
/// X.509 chain header.
pub enum X5Chain {
    One(Vec<u8>),
    Many(Vec<Vec<u8>>),
}

impl Header for X5Chain {
    fn key() -> Key {
        Key::Integer(33)
    }
}

impl From<X5Chain> for Value {
    fn from(value: X5Chain) -> Self {
        match value {
            X5Chain::One(v) => v.into(),
            X5Chain::Many(v) => v
                .into_iter()
                .map(Value::Bytes)
                .collect::<Vec<Value>>()
                .into(),
        }
    }
}

impl TryFrom<Value> for X5Chain {
    type Error = serde_cbor::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(v) => Ok(X5Chain::One(v)),
            Value::Array(v) => v
                .into_iter()
                .map(serde_cbor::value::from_value)
                .collect::<Result<Vec<Vec<u8>>, serde_cbor::Error>>()
                .map(X5Chain::Many),
            _ => Err(serde_cbor::Error::custom("Invalid X5Chain value")),
        }
    }
}

/// Key ID header.
pub struct KeyId(Vec<u8>);

impl KeyId {
    pub fn new(value: impl Into<Vec<u8>>) -> KeyId {
        KeyId(value.into())
    }
}

impl Header for KeyId {
    fn key() -> Key {
        Key::Integer(4)
    }
}

impl From<KeyId> for Value {
    fn from(value: KeyId) -> Self {
        value.0.into()
    }
}

impl TryFrom<Value> for KeyId {
    type Error = serde_cbor::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Bytes(bytes) = value {
            Ok(KeyId(bytes))
        } else {
            Err(serde_cbor::Error::custom("Invalid KeyId value"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{super::HeaderMap, *};

    #[test]
    fn test_key_id() {
        let mut header_map = HeaderMap::default();
        let key_id_bstr = b"test key ID";
        let key_id = KeyId::new(key_id_bstr);
        header_map
            .insert_header(key_id)
            .expect("failed to insert key ID");
        let retrieved = header_map
            .remove_header::<KeyId>()
            .expect("failed to remove key ID")
            .expect("key ID not found");
        assert_eq!(retrieved.0, key_id_bstr);
    }
}
