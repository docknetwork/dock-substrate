use alloc::collections::{BTreeMap, BTreeSet};

use serde::{self, Deserialize, Serialize};

pub mod btree_set {
    use super::*;

    pub fn serialize<T, S, I>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<BTreeSet<I>>,
        BTreeSet<I>: serde::Serialize,
    {
        BTreeSet::serialize(value.as_ref(), serializer)
    }

    pub fn deserialize<'de, D, I, O>(deserializer: D) -> Result<O, D::Error>
    where
        D: serde::Deserializer<'de>,
        BTreeSet<I>: serde::Deserialize<'de> + TryInto<O>,
    {
        BTreeSet::deserialize(deserializer)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("`BTreeSet` size limit exceeded"))
    }
}

pub mod btree_map {
    use super::*;

    pub fn serialize<T, S, K, V>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<BTreeMap<K, V>>,
        BTreeMap<K, V>: serde::Serialize,
    {
        BTreeMap::serialize(value.as_ref(), serializer)
    }

    pub fn deserialize<'de, D, K, V, O>(deserializer: D) -> Result<O, D::Error>
    where
        D: serde::Deserializer<'de>,
        BTreeMap<K, V>: serde::Deserialize<'de> + TryInto<O>,
    {
        BTreeMap::deserialize(deserializer)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("`BTreeMap` size limit exceeded"))
    }
}
