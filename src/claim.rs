use serde::{Deserialize, Serialize};
use serde_cbor::Value;

/// Registered CWT claims from the
/// [CWT Claims registry](https://www.iana.org/assignments/cwt/cwt.xhtml).
pub trait Claim: Into<Value> {
    fn label() -> Label;
}

pub enum Label {
    Text(String),
    Integer(i128),
}
impl From<Label> for Value {
    fn from(label: Label) -> Value {
        match label {
            Label::Text(k) => Value::Text(k),
            Label::Integer(k) => Value::Integer(k),
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
#[macro_export]
macro_rules! define_claim {
    ($name:ident, $value_type: ty, $label: expr) => {
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        pub struct $name($value_type);
        impl $name {
            pub fn new(value: $value_type) -> $name {
                $name(value)
            }
        }

        impl Claim for $name {
            fn label() -> Label {
                $label
            }
        }

        impl From<$name> for Value {
            fn from(value: $name) -> Self {
                value.0.into()
            }
        }
    };
}

define_claim!(Issuer, String, Label::Integer(1));
define_claim!(Subject, String, Label::Integer(2));
define_claim!(Audience, String, Label::Integer(3));
define_claim!(ExpirationTime, NumericDate, Label::Integer(4));
define_claim!(NotBefore, NumericDate, Label::Integer(5));
define_claim!(IssuedAt, NumericDate, Label::Integer(6));
define_claim!(CWTId, Vec<u8>, Label::Integer(7));
