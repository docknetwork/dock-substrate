use super::BoundedKeyValue;
use alloc::collections::{btree_map, BTreeMap, BTreeSet};
use codec::{Decode, Encode, MaxEncodedLen};
use core::ops::{Deref, DerefMut};
use frame_support::*;
use sp_runtime::{DispatchError, Either};

/// Checks whether an actor can update an entity.
pub trait CanUpdate<Entity>: Sized {
    /// Checks whether the new entity can be added.
    #[must_use]
    fn can_add(&self, _new: &Entity) -> bool {
        false
    }

    /// Checks whether the provided entity can replace the existing one.
    #[must_use]
    fn can_replace(&self, _new: &Entity, _current: &Entity) -> bool {
        false
    }

    /// Checks whether the existing entity can be removed.
    #[must_use]
    fn can_remove(&self, _entity: &Entity) -> bool {
        false
    }
}

/// Checks whether an actor can update an entity over some keys.
pub trait CanUpdateKeyed<Entity>
where
    Entity: Deref,
    Entity::Target: BoundedKeyValue,
{
    /// Checks whether the underlying keyed update can be applied, i.e. all associated updates are valid.
    #[must_use]
    fn can_update_keyed<U: KeyedUpdate<Entity>>(&self, _entity: &Entity, _update: &U) -> bool {
        false
    }
}

/// Checks whether an actor can either update a whole entity or some of its keys.
pub trait CanUpdateAndCanUpdateKeyed<Entity>: CanUpdateKeyed<Entity> + CanUpdate<Entity>
where
    Entity: Deref,
    Entity::Target: BoundedKeyValue,
{
}

impl<Entity, T: CanUpdateKeyed<Entity> + CanUpdate<Entity>> CanUpdateAndCanUpdateKeyed<Entity> for T
where
    Entity: Deref,
    Entity::Target: BoundedKeyValue,
{
}

/// Applies an update to the entity.
pub trait ApplyUpdate<Entity> {
    /// Applies update contained in `self` to the supplied entity.
    fn apply_update(self, entity: &mut Entity);

    /// Returns the underlying update's kind.
    fn kind(&self, entity: &Entity) -> UpdateKind;
}

/// Validates underlying update, so it can be safely applied to the supplied entity.
pub trait ValidateUpdate<Actor, Entity>: ApplyUpdate<Entity> {
    /// Ensures that the underlying update is valid.
    fn ensure_valid(&self, actor: &Actor, entity: &Entity) -> Result<(), UpdateError>;
}

/// Describes what will happen when the update will be applied.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UpdateKind {
    Add,
    Remove,
    Replace,
    None,
}

impl Default for UpdateKind {
    fn default() -> Self {
        Self::None
    }
}

impl<T> CanUpdate<()> for T {
    fn can_add(&self, _entity: &()) -> bool {
        true
    }

    fn can_remove(&self, _entity: &()) -> bool {
        true
    }

    fn can_replace(&self, _new: &(), _entity: &()) -> bool {
        true
    }
}

/// Series of updates applied over some targets.
pub trait KeyedUpdate<Entity: Deref>
where
    Entity::Target: BoundedKeyValue,
{
    type Targets<'a>: Iterator<Item = &'a <Entity::Target as BoundedKeyValue>::Key> + 'a
    where
        Self: 'a,
        <Entity::Target as BoundedKeyValue>::Key: 'a,
        Entity: 'a;

    fn targets<'targets>(&'targets self, entity: &'targets Entity) -> Self::Targets<'targets>;

    fn keys_diff(
        &self,
        entity: &Entity,
    ) -> MultiTargetUpdate<<Entity::Target as BoundedKeyValue>::Key, AddOrRemoveOrModify<()>>;

    fn record_inner_keys_diff<K: Ord + Clone>(
        &self,
        entity: &Entity,
        inner_key: K,
        map: &mut MultiTargetUpdate<
            <Entity::Target as BoundedKeyValue>::Key,
            MultiTargetUpdate<K, AddOrRemoveOrModify<()>>,
        >,
    ) -> Result<(), DuplicateKey> {
        for (key, update) in self.keys_diff(entity).0 {
            map.entry(key)
                .or_default()
                .insert_update(inner_key.clone(), update)?;
        }

        Ok(())
    }
}

pub struct DuplicateKey;

impl From<DuplicateKey> for DispatchError {
    fn from(DuplicateKey: DuplicateKey) -> Self {
        Self::Other("Duplicate key")
    }
}

/// Map representing keyed updates applied over dictionary over given keys.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, DefaultNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct MultiTargetUpdate<K: Ord, U>(pub BTreeMap<K, U>);

impl<K, U> FromIterator<(K, U)> for MultiTargetUpdate<K, U>
where
    K: Ord,
{
    fn from_iter<I: IntoIterator<Item = (K, U)>>(iter: I) -> Self {
        Self(FromIterator::from_iter(iter))
    }
}

impl<K: Ord, U> MultiTargetUpdate<K, U> {
    pub fn insert_update(&mut self, key: K, value: U) -> Result<(), DuplicateKey> {
        match self.entry(key) {
            btree_map::Entry::Occupied(_) => {
                Err(DuplicateKey)?;
            }
            btree_map::Entry::Vacant(vacant) => {
                vacant.insert(value);
            }
        }

        Ok(())
    }

    pub fn insert_update_or_remove_duplicate(
        &mut self,
        key: K,
        value: U,
    ) -> Result<(), DuplicateKey> {
        match self.entry(key) {
            btree_map::Entry::Occupied(entry) => {
                entry.remove();
            }
            btree_map::Entry::Vacant(vacant) => {
                vacant.insert(value);
            }
        }

        Ok(())
    }

    pub fn bind_modifier(
        mut f: impl FnMut(&mut Self, K, U) -> Result<(), DuplicateKey>,
        key: K,
        value: U,
    ) -> impl FnMut(&mut Self) -> Result<(), DuplicateKey>
    where
        K: Clone,
        U: Clone,
    {
        move |map| f(map, key.clone(), value.clone())
    }
}

impl<K, U> IntoIterator for MultiTargetUpdate<K, U>
where
    K: Ord,
{
    type Item = (K, U);
    type IntoIter = btree_map::IntoIter<K, U>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

crate::impl_wrapper!(MultiTargetUpdate<K, U> where K: Ord => (BTreeMap<K, U>));

/// Set/add/remove a value or apply a nested update.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum SetOrAddOrRemoveOrModify<V, U = ()> {
    Set(V),
    Add(V),
    Remove,
    Modify(U),
}

/// Add/remove a value or apply a nested update.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum AddOrRemoveOrModify<V, U = ()> {
    Add(V),
    Remove,
    Modify(U),
}

/// Set a value or apply a nested update.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum SetOrModify<V, U = ()> {
    Set(V),
    Modify(U),
}

/// Apply an update to the existing entity.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct OnlyExistent<U>(pub U);

impl<V> ApplyUpdate<V> for () {
    fn apply_update(self, _: &mut V) {}

    fn kind(&self, _: &V) -> UpdateKind {
        UpdateKind::None
    }
}

impl<A, V> ValidateUpdate<A, V> for () {
    fn ensure_valid(&self, _: &A, _: &V) -> Result<(), UpdateError> {
        Ok(())
    }
}

impl<V, U> ApplyUpdate<Option<V>> for OnlyExistent<U>
where
    U: ApplyUpdate<V>,
{
    fn apply_update(self, entity: &mut Option<V>) {
        self.0
            .apply_update(entity.as_mut().expect("`OnlyExistent` update failed"))
    }

    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        entity
            .as_ref()
            .map_or(UpdateKind::None, |entity| self.0.kind(entity))
    }
}

impl<A: CanUpdate<V>, V, U: ValidateUpdate<A, V>> ValidateUpdate<A, Option<V>> for OnlyExistent<U> {
    fn ensure_valid(&self, actor: &A, entity: &Option<V>) -> Result<(), UpdateError> {
        let target = entity.as_ref().ok_or(UpdateError::DoesntExist)?;

        self.0.ensure_valid(actor, target)
    }
}

impl<V, U: ApplyUpdate<Option<V>>> ApplyUpdate<Option<V>> for SetOrAddOrRemoveOrModify<V, U> {
    fn apply_update(self, entity: &mut Option<V>) {
        match self {
            Self::Set(value) => {
                entity.replace(value);
            }
            Self::Add(value) => {
                if entity.replace(value).is_some() {
                    panic!("Entity already exists");
                }
            }
            Self::Remove => {
                entity.take().expect("Can't remove non-existing entity");
            }
            Self::Modify(update) => {
                update.apply_update(entity);
            }
        }
    }

    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        match self {
            Self::Set(_) => {
                if entity.is_none() {
                    UpdateKind::Add
                } else {
                    UpdateKind::Replace
                }
            }
            Self::Add(_) => {
                if entity.is_none() {
                    UpdateKind::Add
                } else {
                    UpdateKind::Replace
                }
            }
            Self::Remove => {
                if entity.is_some() {
                    UpdateKind::Remove
                } else {
                    UpdateKind::None
                }
            }
            Self::Modify(update) => update.kind(entity),
        }
    }
}

impl<A: CanUpdate<V>, V, U: ValidateUpdate<A, Option<V>>> ValidateUpdate<A, Option<V>>
    for SetOrAddOrRemoveOrModify<V, U>
{
    fn ensure_valid(&self, actor: &A, entity: &Option<V>) -> Result<(), UpdateError> {
        match self {
            Self::Set(new) => {
                let cond = match entity {
                    Some(current) => actor.can_replace(new, current),
                    None => actor.can_add(new),
                };

                ensure!(cond, UpdateError::InvalidActor);
            }
            Self::Add(value) => {
                ensure!(actor.can_add(value), UpdateError::InvalidActor);
                ensure!(entity.is_none(), UpdateError::AlreadyExists);
            }
            Self::Remove => {
                let existing = entity.as_ref().ok_or(UpdateError::DoesntExist)?;

                ensure!(actor.can_remove(existing), UpdateError::InvalidActor);
            }
            Self::Modify(update) => return update.ensure_valid(actor, entity),
        };

        Ok(())
    }
}

impl<A: CanUpdate<V>, V, U: ValidateUpdate<A, Option<V>>> ValidateUpdate<A, Option<V>>
    for AddOrRemoveOrModify<V, U>
{
    fn ensure_valid(&self, actor: &A, entity: &Option<V>) -> Result<(), UpdateError> {
        match self {
            Self::Add(value) => {
                ensure!(actor.can_add(value), UpdateError::InvalidActor);
                ensure!(entity.is_none(), UpdateError::AlreadyExists);
            }
            Self::Remove => {
                let existing = entity.as_ref().ok_or(UpdateError::DoesntExist)?;

                ensure!(actor.can_remove(existing), UpdateError::InvalidActor);
            }
            Self::Modify(update) => return update.ensure_valid(actor, entity),
        }

        Ok(())
    }
}

impl<V, U: ApplyUpdate<Option<V>>> ApplyUpdate<Option<V>> for AddOrRemoveOrModify<V, U> {
    fn apply_update(self, entity: &mut Option<V>) {
        match self {
            Self::Add(value) => {
                if entity.replace(value).is_some() {
                    panic!("Entity already exists");
                }
            }
            Self::Remove => {
                entity.take().expect("Can't remove non-existing entity");
            }
            Self::Modify(update) => {
                update.apply_update(entity);
            }
        }
    }

    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        match self {
            Self::Add(_) => {
                if entity.is_none() {
                    UpdateKind::Add
                } else {
                    UpdateKind::Replace
                }
            }
            Self::Remove => {
                if entity.is_some() {
                    UpdateKind::Remove
                } else {
                    UpdateKind::None
                }
            }
            Self::Modify(update) => update.kind(entity),
        }
    }
}

impl<V, U: ApplyUpdate<V>> ApplyUpdate<V> for SetOrModify<V, U> {
    fn apply_update(self, entity: &mut V) {
        match self {
            SetOrModify::Set(value) => {
                *entity = value;
            }
            SetOrModify::Modify(update) => update.apply_update(entity),
        }
    }

    fn kind(&self, entity: &V) -> UpdateKind {
        match self {
            SetOrModify::Set(_) => UpdateKind::Replace,
            SetOrModify::Modify(update) => update.kind(entity),
        }
    }
}

impl<A: CanUpdate<V>, V, U: ValidateUpdate<A, V>> ValidateUpdate<A, V> for SetOrModify<V, U> {
    fn ensure_valid(&self, actor: &A, entity: &V) -> Result<(), UpdateError> {
        match self {
            SetOrModify::Set(new) => {
                ensure!(actor.can_replace(new, entity), UpdateError::InvalidActor);

                Ok(())
            }
            SetOrModify::Modify(update) => update.ensure_valid(actor, entity),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum UpdateError {
    DoesntExist,
    AlreadyExists,
    InvalidActor,
    CapacityOverflow,
    ValidationFailed,
}

impl From<UpdateError> for DispatchError {
    fn from(error: UpdateError) -> Self {
        Self::Other(match error {
            UpdateError::DoesntExist => "Entity doesn't exist",
            UpdateError::AlreadyExists => "Entity already exists",
            UpdateError::InvalidActor => "Provided actor can't perform this action",
            UpdateError::CapacityOverflow => "Capacity overflow",
            UpdateError::ValidationFailed => "Validation failed",
        })
    }
}

impl<U, C> ApplyUpdate<C> for MultiTargetUpdate<<C::Target as BoundedKeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: BoundedKeyValue,
    U: ApplyUpdate<Option<<C::Target as BoundedKeyValue>::Value>>,
{
    fn apply_update(self, entity: &mut C) {
        #[cfg(not(feature = "std"))]
        use alloc::vec::Vec;

        let (remove, rest): (Vec<_>, Vec<_>) = self.0.into_iter().partition(|(key, action)| {
            action.kind(&entity.get(key).cloned()) == UpdateKind::Remove
        });

        remove.into_iter().chain(rest).for_each(|(key, action)| {
            let mut opt = entity.take(&key);
            action.apply_update(&mut opt);

            if let Some(new_value) = opt {
                entity
                    .try_insert(key, new_value)
                    .ok()
                    .expect("`MultiTargetUpdate` update failed");
            }
        });
    }

    fn kind(&self, entity: &C) -> UpdateKind {
        self.iter()
            .any(|(key, update)| update.kind(&entity.get(key).cloned()) != UpdateKind::None)
            .then_some(UpdateKind::Replace)
            .unwrap_or_default()
    }
}

impl<A, U, C> ValidateUpdate<A, C> for MultiTargetUpdate<<C::Target as BoundedKeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: BoundedKeyValue,
    A: CanUpdateKeyed<C>,
    U: ValidateUpdate<A, Option<<C::Target as BoundedKeyValue>::Value>>,
{
    fn ensure_valid(&self, actor: &A, entity: &C) -> Result<(), UpdateError> {
        ensure!(
            actor.can_update_keyed(entity, self),
            UpdateError::InvalidActor
        );

        let new_len = self
            .iter()
            .try_fold(entity.len() as i32, |acc, (key, action)| {
                let value_opt = &entity.get(key).cloned();
                action.ensure_valid(actor, value_opt)?;

                let diff = match action.kind(value_opt) {
                    UpdateKind::Add => 1,
                    UpdateKind::Remove => -1,
                    _ => 0,
                };

                Ok(acc + diff)
            })?;

        if new_len < 0 {
            Err(UpdateError::ValidationFailed)
        } else if new_len as u32 <= entity.capacity() {
            Ok(())
        } else {
            Err(UpdateError::CapacityOverflow)
        }
    }
}

impl<U, C> KeyedUpdate<C> for MultiTargetUpdate<<C::Target as BoundedKeyValue>::Key, U>
where
    C: DerefMut,
    U: ApplyUpdate<Option<<C::Target as BoundedKeyValue>::Value>>,
    C::Target: BoundedKeyValue,
{
    type Targets<'a> = alloc::collections::btree_map::Keys<'a, <C::Target as BoundedKeyValue>::Key, U>  where
    Self: 'a,
    <C::Target as BoundedKeyValue>::Key: 'a,
    C: 'a;

    fn targets<'targets>(&'targets self, _entity: &'targets C) -> Self::Targets<'targets> {
        self.keys()
    }

    fn keys_diff(
        &self,
        entity: &C,
    ) -> MultiTargetUpdate<<C::Target as BoundedKeyValue>::Key, AddOrRemoveOrModify<()>> {
        self.iter()
            .filter_map(|(key, update)| {
                let update = match update.kind(&entity.get(key).cloned()) {
                    UpdateKind::Add => AddOrRemoveOrModify::Add(()),
                    UpdateKind::Remove => AddOrRemoveOrModify::Remove,
                    _ => None?,
                };

                Some((key.clone(), update))
            })
            .collect()
    }
}

impl<U, C> KeyedUpdate<C> for SetOrModify<C, U>
where
    C: DerefMut,
    C::Target: BoundedKeyValue,
    U: KeyedUpdate<C>,
{
    type Targets<'a> = Either<
        core::iter::Chain<
            <C::Target as BoundedKeyValue>::Keys<'a>,
            <C::Target as BoundedKeyValue>::Keys<'a>,
        >,
        U::Targets<'a>
    >  where
    Self: 'a,
    <C::Target as BoundedKeyValue>::Key: 'a,
    C: 'a;

    fn targets<'targets>(&'targets self, entity: &'targets C) -> Self::Targets<'targets> {
        match self {
            Self::Set(item) => Either::Left(item.keys().chain(entity.keys())),
            Self::Modify(update) => Either::Right(update.targets(entity)),
        }
    }

    fn keys_diff(
        &self,
        entity: &C,
    ) -> MultiTargetUpdate<<C::Target as BoundedKeyValue>::Key, AddOrRemoveOrModify<()>> {
        match self {
            Self::Set(item) => {
                let after: BTreeSet<_> = item.keys().collect();
                let before: BTreeSet<_> = entity.keys().collect();

                after
                    .difference(&before)
                    .map(|key| ((*key).clone(), AddOrRemoveOrModify::Add(())))
                    .chain(
                        before
                            .difference(&after)
                            .map(|key| ((*key).clone(), AddOrRemoveOrModify::Remove)),
                    )
                    .collect()
            }
            Self::Modify(update) => update.keys_diff(entity),
        }
    }
}

#[cfg(test)]
mod tests {
    use sp_runtime::{traits::ConstU32, BoundedBTreeMap};

    use crate::util::{
        ApplyUpdate, BoundedKeyValue, CanUpdate, CanUpdateKeyed, KeyedUpdate, UpdateError,
    };

    use super::{AddOrRemoveOrModify, MultiTargetUpdate, ValidateUpdate};

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct S(BoundedBTreeMap<String, u8, ConstU32<5>>);

    crate::impl_wrapper!(S(BoundedBTreeMap<String, u8, ConstU32<5>>));

    struct CanAddAndReplace;
    impl CanUpdateKeyed<S> for CanAddAndReplace {
        fn can_update_keyed<U: crate::util::KeyedUpdate<S>>(
            &self,
            _entity: &S,
            _update: &U,
        ) -> bool {
            true
        }
    }

    impl CanUpdate<u8> for CanAddAndReplace {
        fn can_add(&self, _new: &u8) -> bool {
            true
        }

        fn can_remove(&self, _entity: &u8) -> bool {
            false
        }

        fn can_replace(&self, _new: &u8, _current: &u8) -> bool {
            true
        }
    }

    struct CanDoEverything;
    impl CanUpdateKeyed<S> for CanDoEverything {
        fn can_update_keyed<U: crate::util::KeyedUpdate<S>>(
            &self,
            _entity: &S,
            _update: &U,
        ) -> bool {
            true
        }
    }

    impl CanUpdate<u8> for CanDoEverything {
        fn can_add(&self, _new: &u8) -> bool {
            true
        }

        fn can_remove(&self, _entity: &u8) -> bool {
            true
        }

        fn can_replace(&self, _new: &u8, _current: &u8) -> bool {
            true
        }
    }

    #[test]
    fn trivial_nested_update() {
        let update = MultiTargetUpdate::from_iter([
            ("1".to_string(), AddOrRemoveOrModify::Remove::<_, ()>),
            ("2".to_string(), AddOrRemoveOrModify::Remove::<_, ()>),
        ]);

        let mut entity = S(BoundedBTreeMap::new());
        entity.try_insert("3".to_string(), 4).unwrap();

        assert_eq!(
            update.targets(&entity).collect::<Vec<_>>(),
            vec![&"1".to_string(), &"2".to_string()]
        );
        assert_eq!(update.keys_diff(&entity), Default::default());

        assert_eq!(
            update.ensure_valid(&CanAddAndReplace, &entity),
            Err(UpdateError::DoesntExist)
        );

        let update =
            MultiTargetUpdate::from_iter([("3".to_string(), AddOrRemoveOrModify::Remove::<_, ()>)]);

        assert_eq!(
            update.ensure_valid(&CanAddAndReplace, &entity),
            Err(UpdateError::InvalidActor)
        );

        let update =
            MultiTargetUpdate::from_iter([("2".to_string(), AddOrRemoveOrModify::Add::<_, ()>(1))]);

        let mut cloned_entity = entity.clone();
        update.apply_update(&mut cloned_entity);

        entity.try_insert("2".to_string(), 1).unwrap();

        assert_eq!(cloned_entity, entity);
    }

    #[test]
    fn update_exceeding_capacity() {
        let update: MultiTargetUpdate<String, AddOrRemoveOrModify<u8>> =
            MultiTargetUpdate::from_iter([
                ("2".to_string(), AddOrRemoveOrModify::Add(2)),
                ("4".to_string(), AddOrRemoveOrModify::Add(4)),
                ("6".to_string(), AddOrRemoveOrModify::Add(6)),
                ("8".to_string(), AddOrRemoveOrModify::Add(8)),
                ("10".to_string(), AddOrRemoveOrModify::Add(10)),
                ("1".to_string(), AddOrRemoveOrModify::Remove::<_, ()>),
                ("3".to_string(), AddOrRemoveOrModify::Remove::<_, ()>),
                ("5".to_string(), AddOrRemoveOrModify::Remove::<_, ()>),
                ("7".to_string(), AddOrRemoveOrModify::Remove::<_, ()>),
            ]);

        let mut entity = S(BoundedBTreeMap::new());
        entity.try_insert("1".to_string(), 1).unwrap();
        entity.try_insert("3".to_string(), 3).unwrap();
        entity.try_insert("5".to_string(), 5).unwrap();
        entity.try_insert("7".to_string(), 7).unwrap();

        entity.try_insert("11".to_string(), 11).unwrap();
        entity.try_insert("9".to_string(), 9).unwrap_err();

        assert_eq!(
            update.ensure_valid(&CanDoEverything, &entity),
            Err(UpdateError::CapacityOverflow)
        );

        entity.take("11".to_string()).unwrap();

        assert_eq!(update.ensure_valid(&CanDoEverything, &entity), Ok(()));

        update.apply_update(&mut entity);

        let mut new_entity = S(BoundedBTreeMap::new());
        new_entity.try_insert("2".to_string(), 2).unwrap();
        new_entity.try_insert("4".to_string(), 4).unwrap();
        new_entity.try_insert("6".to_string(), 6).unwrap();
        new_entity.try_insert("8".to_string(), 8).unwrap();
        new_entity.try_insert("10".to_string(), 10).unwrap();

        assert_eq!(new_entity, entity);
    }
}
