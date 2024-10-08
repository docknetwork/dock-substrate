use hex::FromHex;
use serde::{
    self,
    de::{Error, Visitor},
};
use sp_std::{fmt, marker::PhantomData};

struct HexStrVisitor<T>(PhantomData<T>);

impl<'de, T> Visitor<'de> for HexStrVisitor<T>
where
    T: FromHex,
    <T as FromHex>::Error: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a hex encoded string")
    }

    fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        parse_hex(data).map_err(Error::custom)
    }

    fn visit_borrowed_str<E>(self, data: &'de str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        parse_hex(data).map_err(Error::custom)
    }
}

fn parse_hex<T>(data: &str) -> Result<T, <T as hex::FromHex>::Error>
where
    T: hex::FromHex,
{
    FromHex::from_hex(data.strip_prefix("0x").unwrap_or(data))
}

pub mod big_array {
    use crate::util::{self, BigArray};

    use super::*;
    pub fn serialize<'a, T, S>(value: &'a T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: util::BigArray<'a> + hex::ToHex,
    {
        if serializer.is_human_readable() {
            let str: String = value.encode_hex();
            serializer.serialize_str(&format!("0x{}", str))
        } else {
            BigArray::serialize(value, serializer)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: util::BigArray<'de> + hex::FromHex,
        <T as hex::FromHex>::Error: sp_std::fmt::Display,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HexStrVisitor(PhantomData))
        } else {
            BigArray::deserialize(deserializer)
        }
    }
}

mod basic {
    use super::*;

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: serde::Serialize + AsRef<[u8]>,
    {
        if serializer.is_human_readable() {
            let str = hex::encode(value.as_ref());
            serializer.serialize_str(&format!("0x{}", str))
        } else {
            T::serialize(value, serializer)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: serde::Deserialize<'de> + TryFrom<Vec<u8>>,
    {
        if deserializer.is_human_readable() {
            let deserialized_bytes =
                deserializer.deserialize_str(HexStrVisitor::<Vec<u8>>(PhantomData))?;

            T::try_from(deserialized_bytes)
                .map_err(|_| serde::de::Error::custom("Failed to construct a value from hex"))
        } else {
            T::deserialize(deserializer)
        }
    }
}

pub use basic::*;
