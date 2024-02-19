use alloc::collections::{BTreeMap, BTreeSet};
use frame_support::{traits::Get, BoundedBTreeMap, BoundedBTreeSet};
use sp_std::borrow::Borrow;

/// Key-value container with capacity.
pub trait KeyValue: Sized {
    type Key: Ord + Clone;
    type Value: Clone;

    type Keys<'keys>: Iterator<Item = &'keys Self::Key> + 'keys
    where
        Self: 'keys,
        Self::Key: 'keys;

    /// Container capacity.
    fn capacity(&self) -> Option<u32>;
    /// Amount of the contained items.
    fn len(&self) -> u32;
    /// Returns `true` if the underlying container is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns `true` if the underlying container has given the key.
    fn contains_key<K: Borrow<Self::Key>>(&self, key: K) -> bool {
        self.get(key).is_some()
    }
    /// Returns value asssociated with the given key.
    fn get<K: Borrow<Self::Key>>(&self, key: K) -> Option<&Self::Value>;
    /// Takes value asssociated with the given key.
    fn take<K: Borrow<Self::Key>>(&mut self, key: K) -> Option<Self::Value>;
    /// Attempts to insert item in the underlying container.
    fn try_add(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<(), (Self::Key, Self::Value)>;
    /// Produces an iterator emitting underlying keys.
    fn keys(&self) -> Self::Keys<'_>;
}

impl<K: Ord + Clone, V: Clone, S: Get<u32>> KeyValue for BoundedBTreeMap<K, V, S> {
    type Key = K;
    type Value = V;

    type Keys<'keys> = alloc::collections::btree_map::Keys<'keys, K, V> where Self: 'keys, K: 'keys;

    fn capacity(&self) -> Option<u32> {
        Some(S::get())
    }
    fn len(&self) -> u32 {
        self.as_ref().len() as u32
    }
    fn get<Key: Borrow<Self::Key>>(&self, key: Key) -> Option<&Self::Value> {
        self.as_ref().get(key.borrow())
    }
    fn take<Key: Borrow<Self::Key>>(&mut self, key: Key) -> Option<Self::Value> {
        self.remove(key.borrow())
    }
    fn try_add(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<(), (Self::Key, Self::Value)> {
        self.try_insert(key, value).map(drop)
    }

    fn keys(&self) -> Self::Keys<'_> {
        self.as_ref().keys()
    }
}

impl<V: Ord + Clone, S: Get<u32>> KeyValue for BoundedBTreeSet<V, S> {
    type Key = V;
    type Value = ();

    type Keys<'keys> = alloc::collections::btree_set::Iter<'keys, V> where Self: 'keys, V: 'keys;

    fn capacity(&self) -> Option<u32> {
        Some(S::get())
    }
    fn len(&self) -> u32 {
        self.as_ref().len() as u32
    }
    fn get<Key: Borrow<Self::Key>>(&self, key: Key) -> Option<&Self::Value> {
        self.as_ref().get(key.borrow()).map(|_| &())
    }
    fn take<Key: Borrow<Self::Key>>(&mut self, key: Key) -> Option<Self::Value> {
        self.take(key.borrow()).map(drop)
    }
    fn try_add(&mut self, key: Self::Key, (): Self::Value) -> Result<(), (Self::Key, Self::Value)> {
        self.try_insert(key).map(drop).map_err(|key| (key, ()))
    }

    fn keys(&self) -> Self::Keys<'_> {
        self.iter()
    }
}

impl<K: Ord + Clone, V: Clone> KeyValue for BTreeMap<K, V> {
    type Key = K;
    type Value = V;

    type Keys<'keys> = alloc::collections::btree_map::Keys<'keys, K, V> where Self: 'keys, K: 'keys;

    fn capacity(&self) -> Option<u32> {
        None
    }
    fn len(&self) -> u32 {
        self.len() as u32
    }
    fn get<Key: Borrow<Self::Key>>(&self, key: Key) -> Option<&Self::Value> {
        self.get(key.borrow())
    }
    fn take<Key: Borrow<Self::Key>>(&mut self, key: Key) -> Option<Self::Value> {
        self.remove(key.borrow())
    }
    fn try_add(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<(), (Self::Key, Self::Value)> {
        self.insert(key, value);

        Ok(())
    }

    fn keys(&self) -> Self::Keys<'_> {
        self.keys()
    }
}

impl<V: Ord + Clone> KeyValue for BTreeSet<V> {
    type Key = V;
    type Value = ();

    type Keys<'keys> = alloc::collections::btree_set::Iter<'keys, V> where Self: 'keys, V: 'keys;

    fn capacity(&self) -> Option<u32> {
        None
    }
    fn len(&self) -> u32 {
        self.len() as u32
    }
    fn get<Key: Borrow<Self::Key>>(&self, key: Key) -> Option<&Self::Value> {
        self.get(key.borrow()).map(|_| &())
    }
    fn take<Key: Borrow<Self::Key>>(&mut self, key: Key) -> Option<Self::Value> {
        self.take(key.borrow()).map(drop)
    }
    fn try_add(&mut self, key: Self::Key, (): Self::Value) -> Result<(), (Self::Key, Self::Value)> {
        self.insert(key);

        Ok(())
    }

    fn keys(&self) -> Self::Keys<'_> {
        self.iter()
    }
}
