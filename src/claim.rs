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

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Issuer(pub String);
impl Claim for Issuer {
    fn key() -> Key {
        Key::Integer(1)
    }
}
impl From<Issuer> for Value {
    fn from(value: Issuer) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Subject(pub String);
impl Claim for Subject {
    fn key() -> Key {
        Key::Integer(2)
    }
}
impl From<Subject> for Value {
    fn from(value: Subject) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Audience(pub String);
impl Claim for Audience {
    fn key() -> Key {
        Key::Integer(3)
    }
}
impl From<Audience> for Value {
    fn from(value: Audience) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ExpirationTime(pub NumericDate);
impl Claim for ExpirationTime {
    fn key() -> Key {
        Key::Integer(4)
    }
}
impl From<ExpirationTime> for Value {
    fn from(value: ExpirationTime) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct NotBefore(pub NumericDate);
impl Claim for NotBefore {
    fn key() -> Key {
        Key::Integer(5)
    }
}
impl From<NotBefore> for Value {
    fn from(value: NotBefore) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct IssuedAt(pub NumericDate);
impl Claim for IssuedAt {
    fn key() -> Key {
        Key::Integer(6)
    }
}
impl From<IssuedAt> for Value {
    fn from(value: IssuedAt) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CWTId(pub Vec<u8>);
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
