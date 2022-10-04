use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::ops::Deref;

/// COSE headers.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HeaderMap(BTreeMap<Value, Value>);

impl HeaderMap {
    /// Insert a header with an integer label.
    pub fn insert_i<L: Into<i128>>(&mut self, label: L, value: Value) -> Option<Value> {
        self.0.insert(Value::Integer(label.into()), value)
    }

    /// Insert a header with a text label.
    pub fn insert_t<L: Into<String>>(&mut self, label: L, value: Value) -> Option<Value> {
        self.0.insert(Value::Text(label.into()), value)
    }

    /// Retrieve a header value with an integer label.
    pub fn get_i<L: Into<i128>>(&self, label: L) -> Option<&Value> {
        self.0.get(&Value::Integer(label.into()))
    }

    /// Retrieve a header value with a text label.
    pub fn get_t<L: Into<String>>(&self, label: L) -> Option<&Value> {
        self.0.get(&Value::Text(label.into()))
    }
}

impl AsRef<BTreeMap<Value, Value>> for HeaderMap {
    fn as_ref(&self) -> &BTreeMap<Value, Value> {
        &self.0
    }
}

impl Deref for HeaderMap {
    type Target = BTreeMap<Value, Value>;

    fn deref(&self) -> &BTreeMap<Value, Value> {
        &self.0
    }
}

impl From<BTreeMap<Value, Value>> for HeaderMap {
    fn from(m: BTreeMap<Value, Value>) -> Self {
        Self(m)
    }
}
