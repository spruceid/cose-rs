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

/// Numerical representation of seconds relative to the Unix Epoch,
/// as defined in [RFC7049](https://www.rfc-editor.org/rfc/rfc7049#section-2.4.1)
/// with the leading tag 1 omitted.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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

/// Simple macro for defining generic claims with implementations of
/// the Claim and From<> for serde_cbor::Value traits.
/// Custom value_type's must implement From<value_type> for serde_cbor::Value.
// #[macro_export]
macro_rules! define_claim {
    ($name:ident, $value_type: ty, $key: expr) => {
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        pub struct $name($value_type);
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
    };
}

/// Macros for implementing TryFrom<Value, Error = Error>
/// for String and NumericDate to eliminate some boilerplate.
macro_rules! try_from_string {
    ($name:ident) => {
        impl TryFrom<Value> for $name {
            type Error = Error;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                match value {
                    Value::Text(s) => Ok(Self(s)),
                    _ => Err(Error::StringValueRequired),
                }
            }
        }
    };
}
macro_rules! try_from_numeric_date {
    ($name:ident) => {
        impl TryFrom<Value> for $name {
            type Error = Error;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                match value {
                    Value::Integer(i) => Ok(Self(NumericDate::IntegerSeconds(i))),
                    Value::Float(f) => Ok(Self(NumericDate::FractionalSeconds(f))),
                    _ => Err(Error::NumericDateRequired),
                }
            }
        }
    };
}

define_claim!(Issuer, String, Key::Integer(1));
try_from_string!(Issuer);

define_claim!(Subject, String, Key::Integer(2));
try_from_string!(Subject);

define_claim!(Audience, String, Key::Integer(3));
try_from_string!(Audience);

define_claim!(ExpirationTime, NumericDate, Key::Integer(4));
try_from_numeric_date!(ExpirationTime);

define_claim!(NotBefore, NumericDate, Key::Integer(5));
try_from_numeric_date!(NotBefore);

define_claim!(IssuedAt, NumericDate, Key::Integer(6));
try_from_numeric_date!(IssuedAt);

define_claim!(CWTId, Vec<u8>, Key::Integer(7));
impl TryFrom<Value> for CWTId {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bytes(b) => Ok(Self(b)),
            _ => Err(Error::BytesValueRequired),
        }
    }
}

/// Errors that can occur when parsing values into claims.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("claim requires String value")]
    StringValueRequired,
    #[error("claim requires NumericDate (int or float)")]
    NumericDateRequired,
    #[error("claim requires Null value")]
    NullValueRequired,
    #[error("claim requires Bool value")]
    BoolValueRequired,
    #[error("claim requires Integer value")]
    IntegerValueRequired,
    #[error("claim requires Float value")]
    FloatValueRequired,
    #[error("claim requires Bytes value")]
    BytesValueRequired,
    #[error("claim requires Text value")]
    TextValueRequired,
    #[error("claim requires Array value")]
    ArrayValueRequired,
    #[error("claim requires Map value")]
    MapValueRequired,
    #[error("claim requires Tag value")]
    TagValueRequired,
    #[error("parse error")]
    GenericParseError(String),
}
