use serde::{Deserialize, Serialize};
use serde_cbor::Value;

/// Registered CWT claims from the
/// [CWT Claims registry](https://www.iana.org/assignments/cwt/cwt.xhtml).
pub trait Claim: Into<Value> {
    fn key() -> Key;
}

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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum NumericDate {
    Integer(i128),
    Fractional(f64),
}
impl From<NumericDate> for Value {
    fn from(value: NumericDate) -> Self {
        match value {
            NumericDate::Integer(i) => Value::Integer(i),
            NumericDate::Fractional(f) => Value::Float(f),
        }
    }
}

/// Simple macro for defining generic claims with implementations of
/// the Claim and From<> for serde_cbor::Value traits.
/// Custom value_type's must implement From<value_type> for serde_cbor::Value.
#[macro_export]
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

define_claim!(Issuer, String, Key::Integer(1));
define_claim!(Subject, String, Key::Integer(2));
define_claim!(Audience, String, Key::Integer(3));
define_claim!(ExpirationTime, NumericDate, Key::Integer(4));
define_claim!(NotBefore, NumericDate, Key::Integer(5));
define_claim!(IssuedAt, NumericDate, Key::Integer(6));
define_claim!(CWTId, Vec<u8>, Key::Integer(7));
