use frame_support::{traits::Get, BoundedBTreeMap, BoundedBTreeSet};
use sp_std::borrow::Borrow;

/// Key-value container with capacity.
pub trait BoundedKeyValue: Sized {
    type Key: Ord + Clone;
    type Value: Clone;

    type Keys<'keys>: Iterator<Item = &'keys Self::Key> + 'keys
    where
        Self: 'keys,
        Self::Key: 'keys;

    fn capacity(&self) -> u32;
    fn len(&self) -> u32;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn contains_key<K: Borrow<Self::Key>>(&self, key: K) -> bool {
        self.get(key).is_some()
    }
    fn get<K: Borrow<Self::Key>>(&self, key: K) -> Option<&Self::Value>;
    fn take<K: Borrow<Self::Key>>(&mut self, key: K) -> Option<Self::Value>;
    fn try_insert(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<(), (Self::Key, Self::Value)>;

    fn keys(&self) -> Self::Keys<'_>;
}

impl<K: Ord + Clone, V: Clone, S: Get<u32>> BoundedKeyValue for BoundedBTreeMap<K, V, S> {
    type Key = K;
    type Value = V;

    type Keys<'keys> = alloc::collections::btree_map::Keys<'keys, K, V> where Self: 'keys, K: 'keys;

    fn capacity(&self) -> u32 {
        S::get()
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
    fn try_insert(
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

impl<V: Ord + Clone, S: Get<u32>> BoundedKeyValue for BoundedBTreeSet<V, S> {
    type Key = V;
    type Value = ();

    type Keys<'keys> = alloc::collections::btree_set::Iter<'keys, V> where Self: 'keys, V: 'keys;

    fn capacity(&self) -> u32 {
        S::get()
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
    fn try_insert(
        &mut self,
        key: Self::Key,
        (): Self::Value,
    ) -> Result<(), (Self::Key, Self::Value)> {
        self.try_insert(key).map(drop).map_err(|key| (key, ()))
    }

    fn keys(&self) -> Self::Keys<'_> {
        self.iter()
    }
}
