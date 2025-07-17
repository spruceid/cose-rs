pub use crate::cwt::{
    claim::{Claim, Key},
    Error,
};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::ops::Deref;

pub mod headers;

/// COSE headers.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HeaderMap(BTreeMap<Key, Value>);

pub trait Header: Into<Value> + TryFrom<Value, Error = serde_cbor::Error> {
    fn key() -> Key;
}

impl HeaderMap {
    /// Insert a defined CWT header parameter.
    /// Returns an error if the previous value found cannot be parsed
    /// into the expected header structure.
    pub fn insert_header<T: Header>(&mut self, claim: T) -> Result<Option<T>, Error> {
        match self.0.insert(T::key(), claim.into()) {
            None => Ok(None),
            Some(v) => v.try_into().map_or_else(
                |e: serde_cbor::Error| Err(Error::UnableToParseClaim(e.into())),
                |claim| Ok(Some(claim)),
            ),
        }
    }

    /// Insert a header with a given key.
    pub fn insert<T: Into<Key>>(&mut self, key: T, value: Value) -> Option<Value> {
        self.0.insert(key.into(), value)
    }

    /// Insert a header with an integer label.
    pub fn insert_i<L: Into<i128>>(&mut self, label: L, value: Value) -> Option<Value> {
        self.0.insert(Key::Integer(label.into()), value)
    }

    /// Insert a header with a text label.
    pub fn insert_t<L: Into<String>>(&mut self, label: L, value: Value) -> Option<Value> {
        self.0.insert(Key::Text(label.into()), value)
    }

    /// Retrieve a header value with a given key.
    pub fn get<T: Into<Key>>(&self, key: T) -> Option<&Value> {
        self.0.get(&key.into())
    }

    /// Retrieve a header value with an integer label.
    pub fn get_i<L: Into<i128>>(&self, label: L) -> Option<&Value> {
        self.0.get(&Key::Integer(label.into()))
    }

    /// Retrieve a header value with a text label.
    pub fn get_t<L: Into<String>>(&self, label: L) -> Option<&Value> {
        self.0.get(&Key::Text(label.into()))
    }

    /// Remove a defined CWT header parameter.
    /// Returns an error if the removed value cannot be parsed into
    /// the expected header structure.
    pub fn remove_header<T: Header>(&mut self) -> Result<Option<T>, Error> {
        match self.0.remove(&T::key()) {
            None => Ok(None),
            Some(v) => v.try_into().map_or_else(
                |e: serde_cbor::Error| Err(Error::UnableToParseClaim(e.into())),
                |claim| Ok(Some(claim)),
            ),
        }
    }

    /// Remove a header value with a given key.
    pub fn remove<T: Into<Key>>(&mut self, key: T) -> Option<Value> {
        self.0.remove(&key.into())
    }

    /// Remove a header value with an integer key.
    pub fn remove_i<T: Into<i128>>(&mut self, key: T) -> Option<Value> {
        self.0.remove(&Key::Integer(key.into()))
    }

    /// Remove a header value with a text key.
    pub fn remove_t<T: Into<String>>(&mut self, key: T) -> Option<Value> {
        self.0.remove(&Key::Text(key.into()))
    }
}

impl AsRef<BTreeMap<Key, Value>> for HeaderMap {
    fn as_ref(&self) -> &BTreeMap<Key, Value> {
        &self.0
    }
}

impl Deref for HeaderMap {
    type Target = BTreeMap<Key, Value>;

    fn deref(&self) -> &BTreeMap<Key, Value> {
        &self.0
    }
}

impl FromIterator<(Key, Value)> for HeaderMap {
    fn from_iter<T: IntoIterator<Item = (Key, Value)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl TryFrom<BTreeMap<Value, Value>> for HeaderMap {
    type Error = Error;

    fn try_from(m: BTreeMap<Value, Value>) -> Result<Self, Self::Error> {
        m.into_iter()
            .map(|(k, v)| Ok((Key::try_from(k)?, v)))
            .collect()
    }
}

impl From<BTreeMap<Key, Value>> for HeaderMap {
    fn from(m: BTreeMap<Key, Value>) -> Self {
        Self(m)
    }
}

impl IntoIterator for HeaderMap {
    type Item = (Key, Value);

    type IntoIter = <BTreeMap<Key, Value> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
