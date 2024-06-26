//! Claims from the IETF Token Status List spec.

use super::{Claim, Error as ClaimError, Key};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;

/// Status Claim for the Referenced Token, which describes
/// its location in the Status List.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Status {
    pub status_list: StatusList,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct StatusList {
    pub idx: u32,
    pub uri: String,
}

impl Status {
    pub fn new(idx: u32, uri: String) -> Self {
        Status {
            status_list: StatusList { idx, uri },
        }
    }
}

impl Claim for Status {
    fn key() -> Key {
        Key::Integer(65535)
    }
}

impl From<Status> for Value {
    fn from(value: Status) -> Self {
        // Unwrap safety: predictable data structure should not throw an error.
        // Unit-tested route.
        serde_cbor::value::to_value(value).unwrap()
    }
}

impl TryFrom<Value> for Status {
    type Error = ClaimError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(serde_cbor::value::from_value(value)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_encode_decode() {
        let status = Status::new(0, "https://example.com/statuslists/1".into());
        let serialized = serde_cbor::to_vec(&status).expect("failed to serialize Status");
        let deserialized_status: Status =
            serde_cbor::from_slice(&serialized).expect("failed to deserialize into Status");
        assert_eq!(status, deserialized_status);
    }

    #[test]
    fn test_status_structure() {
        let test_uri = "https://example.com/statuslists/1";
        let test_idx = 108;
        let status = Status::new(test_idx, test_uri.into());
        let status_cbor: Value = status.into();
        let expected_status_cbor = Value::Map(BTreeMap::from_iter([(
            Value::Text("status_list".into()),
            Value::Map(BTreeMap::from_iter([
                (Value::Text("idx".into()), Value::Integer(test_idx.into())),
                (Value::Text("uri".into()), Value::Text(test_uri.into())),
            ])),
        )]));
        assert_eq!(expected_status_cbor, status_cbor);
    }
}
