use crate::header_map::HeaderMap;
use serde::{
    de::{self, Error as DeError},
    ser::{self, Error as SerError},
};
use serde_cbor::Value;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, Default)]
pub struct Protected(HeaderMap, Option<Vec<u8>>);

impl ser::Serialize for Protected {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        Value::try_from(self.clone())
            .map_err(S::Error::custom)?
            .serialize(s)
    }
}

impl<'de> de::Deserialize<'de> for Protected {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        match Value::deserialize(d)? {
            Value::Bytes(header_map_bytes) => {
                let header_map = if header_map_bytes.is_empty() {
                    HeaderMap::default()
                } else {
                    serde_cbor::from_slice(&header_map_bytes).map_err(D::Error::custom)?
                };
                Ok(Protected(header_map, Some(header_map_bytes)))
            }
            v => Err(D::Error::custom(format!(
                "expected byte str, found: {:?}",
                v
            ))),
        }
    }
}

impl TryFrom<Protected> for Value {
    type Error = serde_cbor::Error;

    fn try_from(p: Protected) -> Result<Value, Self::Error> {
        if let Some(bytes) = p.1 {
            if p.0 == serde_cbor::from_slice(&bytes)? {
                return Ok(Value::Bytes(bytes));
            }
        }
        let header_map_bytes = if p.0.is_empty() {
            vec![]
        } else {
            serde_cbor::to_vec(&p.0)?
        };

        Ok(Value::Bytes(header_map_bytes))
    }
}

impl AsRef<HeaderMap> for Protected {
    fn as_ref(&self) -> &HeaderMap {
        &self.0
    }
}

impl AsMut<HeaderMap> for Protected {
    fn as_mut(&mut self) -> &mut HeaderMap {
        &mut self.0
    }
}

impl Deref for Protected {
    type Target = HeaderMap;

    fn deref(&self) -> &HeaderMap {
        &self.0
    }
}

impl DerefMut for Protected {
    fn deref_mut(&mut self) -> &mut HeaderMap {
        &mut self.0
    }
}

impl From<HeaderMap> for Protected {
    fn from(h: HeaderMap) -> Self {
        Self(h, None)
    }
}
