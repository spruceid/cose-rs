use serde_cbor::Value;

/// Registered CWT claims from the
/// [CWT Claims registry](https://www.iana.org/assignments/cwt/cwt.xhtml).
pub enum IANAClaim {
    Issuer(&'static str),
    Subject(&'static str),
    Audience(&'static str),
    ExpirationTime(i128), // TODO EN: these should technically also allow for fractional (float) time
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
