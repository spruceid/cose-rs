use serde_cbor::Value;

/// Registered CWT claims from the
/// [CWT Claims registry](https://www.iana.org/assignments/cwt/cwt.xhtml).
pub enum Claim {
    Issuer(&'static str),
    Subject(&'static str),
    Audience(&'static str),
    ExpirationTime(i128), // TODO EN: these should technically also allow for fractional (float) time
    NotBefore(i128),
    IssuedAt(i128),
    CWTId(Vec<u8>),
}

impl Claim {
    pub fn key(&self) -> i128 {
        match self {
            Claim::Issuer(_) => 1,
            Claim::Subject(_) => 2,
            Claim::Audience(_) => 3,
            Claim::ExpirationTime(_) => 4,
            Claim::NotBefore(_) => 5,
            Claim::IssuedAt(_) => 6,
            Claim::CWTId(_) => 7,
        }
    }

    pub fn value(&self) -> Value {
        match self {
            Claim::Issuer(value) => Value::Text(value.to_string()),
            Claim::Subject(value) => Value::Text(value.to_string()),
            Claim::Audience(value) => Value::Text(value.to_string()),
            Claim::ExpirationTime(value) => Value::Integer(*value), // TODO EN: these should technically also allow for fractional time...
            Claim::NotBefore(value) => Value::Integer(*value),
            Claim::IssuedAt(value) => Value::Integer(*value),
            Claim::CWTId(value) => Value::Bytes(value.to_vec()),
        }
    }
}
