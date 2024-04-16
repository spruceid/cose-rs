use serde::{Deserialize, Serialize};
use serde_cbor::Value;

/// Representation of CWT claims, as defined in
/// [RFC8392](https://datatracker.ietf.org/doc/html/rfc8392).
pub trait Claim: Into<Value> + TryFrom<Value, Error = Error> {
    fn key() -> Key;
}

/// Representation of the CBOR map key used to identify a claim
/// within a CWT claims set, and restricted to text and integer values,
/// per [RFC8392](https://datatracker.ietf.org/doc/html/rfc8392).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
#[serde(try_from = "Value", into = "Value")]
pub enum Key {
    Text(String),
    Integer(i128),
}

impl From<Key> for Value {
    fn from(key: Key) -> Value {
        match key {
            Key::Text(k) => Value::Text(k),
            Key::Integer(k) => Value::Integer(k),
        }
    }
}

impl TryFrom<Value> for Key {
    type Error = super::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Text(s) => Ok(Key::Text(s)),
            Value::Integer(i) => Ok(Key::Integer(i)),
            invalid_key_type => Err(Self::Error::InvalidCwtKey(format!(
                "{:?}",
                invalid_key_type
            ))),
        }
    }
}

impl From<String> for Key {
    fn from(key: String) -> Self {
        Key::Text(key)
    }
}

impl From<i128> for Key {
    fn from(key: i128) -> Self {
        Key::Integer(key)
    }
}

/// Errors that can occur when parsing values into claims.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("claim requires NumericDate (int or float)")]
    NumericDateRequired,
    #[error("claim requires Bytes value")]
    BytesValueRequired,
    #[error("conversion error: {0}")]
    ConversionError(#[from] serde_cbor::Error),
}

/// Numerical representation of seconds relative to the Unix Epoch,
/// as defined in [RFC7049](https://www.rfc-editor.org/rfc/rfc7049#section-2.4.1)
/// with the leading tag 1 omitted.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd)]
#[serde(try_from = "Value", into = "Value")]
pub enum NumericDate {
    IntegerSeconds(i128),
    FractionalSeconds(f64),
}

impl From<NumericDate> for Value {
    fn from(value: NumericDate) -> Self {
        match value {
            NumericDate::IntegerSeconds(i) => Value::Integer(i),
            NumericDate::FractionalSeconds(f) => Value::Float(f),
        }
    }
}

impl TryFrom<Value> for NumericDate {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Integer(i) => Ok(NumericDate::IntegerSeconds(i)),
            Value::Float(f) => Ok(NumericDate::FractionalSeconds(f)),
            _ => Err(Error::NumericDateRequired),
        }
    }
}

/// Simple macro for defining generic claims with implementations of
/// the Claim and From<> for serde_cbor::Value traits.
/// Custom value_type's must implement From<value_type> for serde_cbor::Value.
macro_rules! define_claim {
    ($name:ident, $value_type: ty, $key: expr) => {
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd)]
        pub struct $name(pub $value_type);
        impl $name {
            pub fn new(value: $value_type) -> $name {
                $name(value)
            }
        }

        impl Claim for $name {
            fn key() -> Key {
                $key
            }
        }

        impl From<$name> for Value {
            fn from(value: $name) -> Self {
                value.0.into()
            }
        }

        impl TryFrom<Value> for $name {
            type Error = Error;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                Ok(Self(serde_cbor::value::from_value(value)?))
            }
        }
    };
}

define_claim!(Issuer, String, Key::Integer(1));
define_claim!(Subject, String, Key::Integer(2));
define_claim!(Audience, String, Key::Integer(3));
define_claim!(ExpirationTime, NumericDate, Key::Integer(4));
define_claim!(NotBefore, NumericDate, Key::Integer(5));
define_claim!(IssuedAt, NumericDate, Key::Integer(6));

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[serde(try_from = "Value", into = "Value")]
pub struct CWTId(Vec<u8>);
impl CWTId {
    pub fn new(value: Vec<u8>) -> CWTId {
        CWTId(value)
    }
}

impl Claim for CWTId {
    fn key() -> Key {
        Key::Integer(7)
    }
}

impl From<CWTId> for Value {
    fn from(value: CWTId) -> Self {
        value.0.into()
    }
}

impl TryFrom<Value> for CWTId {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Bytes(bytes) = value {
            Ok(CWTId(bytes))
        } else {
            Err(Error::BytesValueRequired)
        }
    }
}
