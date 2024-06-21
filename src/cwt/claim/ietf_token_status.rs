//! Claims from the IETF Token Status List spec.

use super::{Claim, Error as ClaimError, Key};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;

/// Status Claim for the ReferencedToken.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct ReferencedTokenStatus {
    pub status_list: StatusListReference,
}

/// Claim describing the location of the Referenced Token in the Status List.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct StatusListReference {
    pub idx: StatusListIndex,
    pub uri: StatusListUri,
}

/// Index to check for status information in the Status List for the Referenced Token.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct StatusListIndex(pub u32);

/// The URI where one can fetch the Status List or Status List Token
/// containing the status information about the ReferencedToken.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct StatusListUri(pub String);

impl ReferencedTokenStatus {
    pub fn new(idx: StatusListIndex, uri: StatusListUri) -> Self {
        Self {
            status_list: StatusListReference { idx, uri },
        }
    }
}

impl Claim for ReferencedTokenStatus {
    fn key() -> Key {
        Key::Integer(65535)
    }
}
impl From<ReferencedTokenStatus> for Value {
    fn from(value: ReferencedTokenStatus) -> Self {
        Value::Map(value.into())
    }
}
impl From<ReferencedTokenStatus> for BTreeMap<Value, Value> {
    fn from(value: ReferencedTokenStatus) -> Self {
        BTreeMap::from_iter([(StatusListReference::key().into(), value.status_list.into())])
    }
}
impl TryFrom<Value> for ReferencedTokenStatus {
    type Error = ClaimError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(serde_cbor::value::from_value(value)?)
    }
}

impl Claim for StatusListReference {
    fn key() -> Key {
        Key::Text("status_list".into())
    }
}
impl From<StatusListReference> for Value {
    fn from(value: StatusListReference) -> Self {
        Value::Map(value.into())
    }
}
impl From<StatusListReference> for BTreeMap<Value, Value> {
    fn from(value: StatusListReference) -> Self {
        BTreeMap::from_iter([
            (StatusListIndex::key().into(), value.idx.into()),
            (StatusListUri::key().into(), value.uri.into()),
        ])
    }
}
impl TryFrom<Value> for StatusListReference {
    type Error = ClaimError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(serde_cbor::value::from_value(value)?)
    }
}

impl From<u32> for StatusListIndex {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl Claim for StatusListIndex {
    fn key() -> Key {
        Key::Text("idx".into())
    }
}
impl From<StatusListIndex> for Value {
    fn from(value: StatusListIndex) -> Self {
        value.0.into()
    }
}
impl TryFrom<Value> for StatusListIndex {
    type Error = ClaimError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(Self(serde_cbor::value::from_value(value)?))
    }
}

impl From<String> for StatusListUri {
    fn from(value: String) -> Self {
        Self(value)
    }
}
impl Claim for StatusListUri {
    fn key() -> Key {
        Key::Text("uri".into())
    }
}
impl From<StatusListUri> for Value {
    fn from(value: StatusListUri) -> Self {
        value.0.into()
    }
}
impl TryFrom<Value> for StatusListUri {
    type Error = ClaimError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(Self(serde_cbor::value::from_value(value)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let status = ReferencedTokenStatus {
            status_list: StatusListReference {
                idx: StatusListIndex(0),
                uri: StatusListUri("https://example.com/statuslists/1".into()),
            },
        };
        let serialized = serde_cbor::to_vec(&status).expect("failed to serialize Status");
        let deserialized_status: ReferencedTokenStatus =
            serde_cbor::from_slice(&serialized).expect("failed to deserialize into Status");

        assert_eq!(status, deserialized_status);
    }
}
