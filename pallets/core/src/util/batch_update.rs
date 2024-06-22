use super::KeyValue;
use alloc::collections::{btree_map, BTreeMap, BTreeSet};
use codec::{Decode, Encode, MaxEncodedLen};
use core::{
    convert::Infallible,
    iter::once,
    num::NonZeroU32,
    ops::{Deref, DerefMut},
};
use frame_support::*;
use itertools::{EitherOrBoth, Itertools};
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
    Entity::Target: KeyValue,
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
    Entity::Target: KeyValue,
{
}

impl<Entity, T: CanUpdateKeyed<Entity> + CanUpdate<Entity>> CanUpdateAndCanUpdateKeyed<Entity> for T
where
    Entity: Deref,
    Entity::Target: KeyValue,
{
}

/// Applies an update to the entity.
pub trait ApplyUpdate<Entity>: GetUpdateKind<Entity> {
    /// Applies update contained in `self` to the supplied entity.
    fn apply_update(self, entity: &mut Entity);
}

impl<V> ApplyUpdate<V> for () {
    fn apply_update(self, _: &mut V) {}
}

/// Combines two updates together if possible.
pub trait CombineUpdates {
    type Combined;
    type Error;

    fn combine(self, other: Self) -> Result<Self::Combined, Self::Error>;
}

/// Returns the underlying update's kind.
pub trait GetUpdateKind<Entity> {
    /// Returns the underlying update's kind.
    fn kind(&self, entity: &Entity) -> UpdateKind;
}

impl<E, U> GetUpdateKind<E> for &'_ U
where
    U: GetUpdateKind<E>,
{
    fn kind(&self, entity: &E) -> UpdateKind {
        (*self).kind(entity)
    }
}

impl<V> GetUpdateKind<V> for () {
    fn kind(&self, _: &V) -> UpdateKind {
        UpdateKind::None
    }
}

/// Attempts to translate underlying update to the `ToUpdate`.
pub trait TranslateUpdate<ToUpdate>: Sized {
    /// Update translation error.
    type Error;

    /// Attempts to translate underlying update to the `ToUpdate`.
    fn translate_update(self) -> Result<ToUpdate, Self::Error>;
}

impl TranslateUpdate<()> for () {
    type Error = Infallible;

    fn translate_update(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// An error that occured during update translation.
pub enum UpdateTranslationError<V, U> {
    Value(V),
    Update(U),
}

/// Validates underlying update, so it can be safely applied to the supplied entity.
pub trait ValidateUpdate<Actor, Entity>: GetUpdateKind<Entity> {
    /// Ensures that the underlying update is valid.
    fn ensure_valid(&self, actor: &Actor, entity: &Entity) -> Result<(), UpdateError>;
}

impl<A, E, U> ValidateUpdate<A, E> for &'_ U
where
    U: ValidateUpdate<A, E>,
{
    fn ensure_valid(&self, actor: &A, entity: &E) -> Result<(), UpdateError> {
        (*self).ensure_valid(actor, entity)
    }
}

impl<A, V> ValidateUpdate<A, V> for () {
    fn ensure_valid(&self, _: &A, _: &V) -> Result<(), UpdateError> {
        Ok(())
    }
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

pub struct DuplicateKey;

impl From<DuplicateKey> for DispatchError {
    fn from(DuplicateKey: DuplicateKey) -> Self {
        Self::Other("Duplicate key")
    }
}

/// Series of updates applied over some targets.
pub trait KeyedUpdate<Entity: Deref>
where
    Entity::Target: KeyValue,
{
    type Targets<'targets>: Iterator<Item = &'targets <Entity::Target as KeyValue>::Key> + 'targets
    where
        Self: 'targets,
        <Entity::Target as KeyValue>::Key: 'targets,
        Entity: 'targets;

    fn size(&self) -> u32;

    fn targets<'targets>(&'targets self, entity: &'targets Entity) -> Self::Targets<'targets>;

    fn keys_diff(
        &self,
        entity: &Entity,
    ) -> MultiTargetUpdate<<Entity::Target as KeyValue>::Key, AddOrRemoveOrModify<()>>;

    fn record_inner_keys_diff<K: Ord + Clone>(
        &self,
        entity: &Entity,
        inner_key: K,
        map: &mut MultiTargetUpdate<
            <Entity::Target as KeyValue>::Key,
            MultiTargetUpdate<K, AddOrRemoveOrModify<()>>,
        >,
    ) -> Result<(), DuplicateKey> {
        for (key, update) in self.keys_diff(entity) {
            map.entry(key)
                .or_default()
                .insert_update(inner_key.clone(), update)?;
        }

        Ok(())
    }
}

/// Map representing keyed updates applied over given keys.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, DefaultNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct MultiTargetUpdate<K: Ord, U>(pub BTreeMap<K, U>);

crate::impl_wrapper!(MultiTargetUpdate<K, U> where K: Ord => (BTreeMap<K, U>));

// Applies the underlying updates map to the entity map containing the data.
impl<U, C> ApplyUpdate<C> for MultiTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: KeyValue,
    U: ApplyUpdate<Option<<C::Target as KeyValue>::Value>>,
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
                    .try_add(key, new_value)
                    .ok()
                    .expect("`MultiTargetUpdate` update failed");
            }
        });
    }
}

impl<U, C> GetUpdateKind<C> for MultiTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: KeyValue,
    U: GetUpdateKind<Option<<C::Target as KeyValue>::Value>>,
{
    fn kind(&self, entity: &C) -> UpdateKind {
        // If any of the underlying updates is not `None`, return `UpdateKind::Replace`; otherwise, return the default `UpdateKind`.
        self.iter()
            .any(|(key, update)| update.kind(&entity.get(key).cloned()) != UpdateKind::None)
            .then_some(UpdateKind::Replace)
            .unwrap_or_default()
    }
}

impl<A, U, C> ValidateUpdate<A, C> for MultiTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: KeyValue,
    A: CanUpdateKeyed<C>,
    U: ValidateUpdate<A, Option<<C::Target as KeyValue>::Value>>,
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
        } else if entity.capacity().map_or(true, |cap| new_len as u32 <= cap) {
            Ok(())
        } else {
            Err(UpdateError::CapacityOverflow)
        }
    }
}

impl<K: Ord, U> CombineUpdates for MultiTargetUpdate<K, U>
where
    U: CombineUpdates<Combined = U>,
{
    type Combined = MultiTargetUpdate<K, U::Combined>;
    type Error = U::Error;

    fn combine(self, other: Self) -> Result<Self::Combined, Self::Error> {
        use EitherOrBoth::*;

        self.0
            .into_iter()
            .merge_join_by(other.0, |(k1, _), (k2, _)| k1.cmp(k2))
            .map(|either| {
                Ok(match either {
                    Left((key, update)) | Right((key, update)) => (key, update),
                    Both((key, left_update), (_key, right_update)) => {
                        (key, left_update.combine(right_update)?)
                    }
                })
            })
            .collect()
    }
}

impl<U, C> KeyedUpdate<C> for MultiTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    U: GetUpdateKind<Option<<C::Target as KeyValue>::Value>>,
    C::Target: KeyValue,
{
    type Targets<'a> = alloc::collections::btree_map::Keys<'a, <C::Target as KeyValue>::Key, U>  where
    Self: 'a,
    <C::Target as KeyValue>::Key: 'a,
    C: 'a;

    fn targets<'targets>(&'targets self, _entity: &'targets C) -> Self::Targets<'targets> {
        self.keys()
    }

    fn size(&self) -> u32 {
        self.0.len() as u32
    }

    fn keys_diff(
        &self,
        entity: &C,
    ) -> MultiTargetUpdate<<C::Target as KeyValue>::Key, AddOrRemoveOrModify<()>> {
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

impl<K, U, KK, UU> TranslateUpdate<MultiTargetUpdate<KK, UU>> for MultiTargetUpdate<K, U>
where
    K: TryInto<KK> + Ord,
    U: TranslateUpdate<UU>,
    KK: Ord,
{
    type Error = UpdateTranslationError<K::Error, U::Error>;

    fn translate_update(self) -> Result<MultiTargetUpdate<KK, UU>, Self::Error> {
        self.into_iter()
            .map(|(key, update)| {
                Ok((
                    key.try_into().map_err(UpdateTranslationError::Value)?,
                    update
                        .translate_update()
                        .map_err(UpdateTranslationError::Update)?,
                ))
            })
            .collect()
    }
}

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

    pub fn insert_update_or_remove_duplicate_if(
        &mut self,
        key: K,
        value: U,
        mut remove_if: impl FnMut(&U) -> bool,
    ) -> Result<(), DuplicateKey>
    where
        U:,
    {
        match self.entry(key) {
            btree_map::Entry::Occupied(entry) => {
                if (remove_if)(entry.get()) {
                    entry.remove();
                } else {
                    Err(DuplicateKey)?
                }
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

/// A single key-value entry representing a keyed update applied over given key.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct SingleTargetUpdate<K, U> {
    key: K,
    update: U,
}

impl<K: Ord, U> SingleTargetUpdate<K, U> {
    pub fn new(key: K, update: U) -> Self {
        Self { key, update }
    }

    fn with_cloned_key(&self) -> SingleTargetUpdate<K, &'_ U>
    where
        K: Clone,
    {
        let Self { key, update } = self;

        SingleTargetUpdate {
            key: key.clone(),
            update,
        }
    }
}

impl<U, C> ApplyUpdate<C> for SingleTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: KeyValue,
    U: ApplyUpdate<Option<<C::Target as KeyValue>::Value>>,
{
    fn apply_update(self, entity: &mut C) {
        MultiTargetUpdate::from(self).apply_update(entity)
    }
}

impl<U, C> GetUpdateKind<C> for SingleTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: KeyValue,
    U: GetUpdateKind<Option<<C::Target as KeyValue>::Value>>,
{
    fn kind(&self, entity: &C) -> UpdateKind {
        (self.update.kind(&entity.get(&self.key).cloned()) != UpdateKind::None)
            .then_some(UpdateKind::Replace)
            .unwrap_or_default()
    }
}

impl<A, U, C> ValidateUpdate<A, C> for SingleTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    C::Target: KeyValue,
    A: CanUpdateKeyed<C>,
    U: ValidateUpdate<A, Option<<C::Target as KeyValue>::Value>>,
{
    fn ensure_valid(&self, actor: &A, entity: &C) -> Result<(), UpdateError> {
        MultiTargetUpdate::from(self).ensure_valid(actor, entity)
    }
}

impl<K: Ord, U> CombineUpdates for SingleTargetUpdate<K, U>
where
    U: CombineUpdates<Combined = U>,
{
    type Combined = MultiTargetUpdate<K, U::Combined>;
    type Error = U::Error;

    fn combine(self, other: Self) -> Result<Self::Combined, Self::Error> {
        MultiTargetUpdate::from(self).combine(other.into())
    }
}

impl<U, C> KeyedUpdate<C> for SingleTargetUpdate<<C::Target as KeyValue>::Key, U>
where
    C: DerefMut,
    U: GetUpdateKind<Option<<C::Target as KeyValue>::Value>>,
    C::Target: KeyValue,
{
    type Targets<'a> = core::iter::Once<&'a <C::Target as KeyValue>::Key> where U: 'a, C: 'a, <C::Target as KeyValue>::Key: 'a;

    fn targets<'targets>(&'targets self, _entity: &'targets C) -> Self::Targets<'targets> {
        once(&self.key)
    }

    fn size(&self) -> u32 {
        1u32
    }

    fn keys_diff(
        &self,
        entity: &C,
    ) -> MultiTargetUpdate<<C::Target as KeyValue>::Key, AddOrRemoveOrModify<()>> {
        let update = match self.kind(entity) {
            UpdateKind::Add => AddOrRemoveOrModify::Add(()),
            UpdateKind::Remove => AddOrRemoveOrModify::Remove,
            _ => return Default::default(),
        };

        SingleTargetUpdate::new(self.key.clone(), update).into()
    }
}

impl<K, U, KK, UU> TranslateUpdate<SingleTargetUpdate<KK, UU>> for SingleTargetUpdate<K, U>
where
    K: TryInto<KK> + Ord,
    U: TranslateUpdate<UU>,
    KK: Ord,
{
    type Error = UpdateTranslationError<K::Error, U::Error>;

    fn translate_update(self) -> Result<SingleTargetUpdate<KK, UU>, Self::Error> {
        let Self { key, update } = self;

        Ok(SingleTargetUpdate::new(
            key.try_into().map_err(UpdateTranslationError::Value)?,
            update
                .translate_update()
                .map_err(UpdateTranslationError::Update)?,
        ))
    }
}

impl<K: Ord, U> From<SingleTargetUpdate<K, U>> for MultiTargetUpdate<K, U> {
    fn from(SingleTargetUpdate { key, update }: SingleTargetUpdate<K, U>) -> Self {
        Self::from_iter(once((key, update)))
    }
}

impl<'a, K: Ord + Clone, U> From<&'a SingleTargetUpdate<K, U>> for MultiTargetUpdate<K, &'a U> {
    fn from(update: &'a SingleTargetUpdate<K, U>) -> Self {
        Self::from(update.with_cloned_key())
    }
}

/// Set/add/remove a value or apply a nested update.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Copy, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum SetOrAddOrRemoveOrModify<V, U = ()> {
    Set(V),
    Add(V),
    Remove,
    Modify(U),
}

impl<V: PartialEq, U: ApplyUpdate<Option<V>>> ApplyUpdate<Option<V>>
    for SetOrAddOrRemoveOrModify<V, U>
{
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
}

impl<V: PartialEq, U: GetUpdateKind<Option<V>>> GetUpdateKind<Option<V>>
    for SetOrAddOrRemoveOrModify<V, U>
{
    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        match self {
            Self::Set(new_value) => {
                if entity.is_none() {
                    UpdateKind::Add
                } else if entity.as_ref().map_or(false, |value| new_value == value) {
                    UpdateKind::None
                } else {
                    UpdateKind::Replace
                }
            }
            Self::Add(_) => {
                if entity.is_none() {
                    UpdateKind::Add
                } else {
                    UpdateKind::None
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

impl<A: CanUpdate<V>, V: PartialEq, U: ValidateUpdate<A, Option<V>>> ValidateUpdate<A, Option<V>>
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

impl<V, U, VV, UU> TranslateUpdate<SetOrAddOrRemoveOrModify<VV, UU>>
    for SetOrAddOrRemoveOrModify<V, U>
where
    V: TryInto<VV>,
    U: TranslateUpdate<UU>,
{
    type Error = UpdateTranslationError<V::Error, U::Error>;

    fn translate_update(self) -> Result<SetOrAddOrRemoveOrModify<VV, UU>, Self::Error> {
        match self {
            Self::Set(value) => value
                .try_into()
                .map_err(UpdateTranslationError::Value)
                .map(SetOrAddOrRemoveOrModify::Set),
            Self::Add(value) => value
                .try_into()
                .map_err(UpdateTranslationError::Value)
                .map(SetOrAddOrRemoveOrModify::Add),
            Self::Remove => Ok(SetOrAddOrRemoveOrModify::Remove),
            Self::Modify(update) => update
                .translate_update()
                .map_err(UpdateTranslationError::Update)
                .map(SetOrAddOrRemoveOrModify::Modify),
        }
    }
}
/// Add/remove a value or apply a nested update.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Copy, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum AddOrRemoveOrModify<V, U = ()> {
    Add(V),
    Remove,
    Modify(U),
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
}

impl<V, U: GetUpdateKind<Option<V>>> GetUpdateKind<Option<V>> for AddOrRemoveOrModify<V, U> {
    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        match self {
            Self::Add(_) => {
                if entity.is_none() {
                    UpdateKind::Add
                } else {
                    UpdateKind::None
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

impl<V, U, VV, UU> TranslateUpdate<AddOrRemoveOrModify<VV, UU>> for AddOrRemoveOrModify<V, U>
where
    V: TryInto<VV>,
    U: TranslateUpdate<UU>,
{
    type Error = UpdateTranslationError<V::Error, U::Error>;

    fn translate_update(self) -> Result<AddOrRemoveOrModify<VV, UU>, Self::Error> {
        match self {
            Self::Add(value) => value
                .try_into()
                .map_err(UpdateTranslationError::Value)
                .map(AddOrRemoveOrModify::Add),
            Self::Remove => Ok(AddOrRemoveOrModify::Remove),
            Self::Modify(update) => update
                .translate_update()
                .map_err(UpdateTranslationError::Update)
                .map(AddOrRemoveOrModify::Modify),
        }
    }
}

/// Set a value or apply a nested update.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Copy, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum SetOrModify<V, U = ()> {
    Set(V),
    Modify(U),
}

impl<V, U> SetOrModify<V, U> {
    pub fn unwrap_modify(self) -> U {
        match self {
            Self::Modify(update) => update,
            Self::Set(_) => panic!("Panic on `SetOrModify::Set`"),
        }
    }
}

impl<V: PartialEq, U: ApplyUpdate<V>> ApplyUpdate<V> for SetOrModify<V, U> {
    fn apply_update(self, entity: &mut V) {
        match self {
            SetOrModify::Set(value) => {
                *entity = value;
            }
            SetOrModify::Modify(update) => update.apply_update(entity),
        }
    }
}

impl<V: PartialEq, U: GetUpdateKind<V>> GetUpdateKind<V> for SetOrModify<V, U> {
    fn kind(&self, entity: &V) -> UpdateKind {
        match self {
            SetOrModify::Set(new_value) => {
                if new_value == entity {
                    UpdateKind::None
                } else {
                    UpdateKind::Replace
                }
            }
            SetOrModify::Modify(update) => update.kind(entity),
        }
    }
}

impl<A: CanUpdate<V>, V: PartialEq, U: ValidateUpdate<A, V>> ValidateUpdate<A, V>
    for SetOrModify<V, U>
{
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

impl<V, U, VV, UU> TranslateUpdate<SetOrModify<VV, UU>> for SetOrModify<V, U>
where
    V: TryInto<VV>,
    U: TranslateUpdate<UU>,
{
    type Error = UpdateTranslationError<V::Error, U::Error>;

    fn translate_update(self) -> Result<SetOrModify<VV, UU>, Self::Error> {
        match self {
            SetOrModify::Set(value) => value
                .try_into()
                .map_err(UpdateTranslationError::Value)
                .map(SetOrModify::Set),
            SetOrModify::Modify(update) => update
                .translate_update()
                .map_err(UpdateTranslationError::Update)
                .map(SetOrModify::Modify),
        }
    }
}

impl<U, C> KeyedUpdate<C> for SetOrModify<C, U>
where
    C: DerefMut,
    C::Target: KeyValue,
    U: KeyedUpdate<C>,
{
    type Targets<'a> = Either<
        core::iter::Chain<
            <C::Target as KeyValue>::Keys<'a>,
            <C::Target as KeyValue>::Keys<'a>,
        >,
        U::Targets<'a>
    >  where
    Self: 'a,
    <C::Target as KeyValue>::Key: 'a,
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
    ) -> MultiTargetUpdate<<C::Target as KeyValue>::Key, AddOrRemoveOrModify<()>> {
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

    fn size(&self) -> u32 {
        match self {
            Self::Set(item) => item.len(),
            Self::Modify(update) => update.size(),
        }
    }
}

/// Apply an update to the existing entity.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Copy, MaxEncodedLen, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct OnlyExistent<U>(pub U);

impl<V, U> ApplyUpdate<Option<V>> for OnlyExistent<U>
where
    U: ApplyUpdate<V>,
{
    fn apply_update(self, entity: &mut Option<V>) {
        self.0
            .apply_update(entity.as_mut().expect("`OnlyExistent` update failed"))
    }
}

impl<V, U> GetUpdateKind<Option<V>> for OnlyExistent<U>
where
    U: GetUpdateKind<V>,
{
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

impl<U, UU> TranslateUpdate<OnlyExistent<UU>> for OnlyExistent<U>
where
    U: TranslateUpdate<UU>,
{
    type Error = U::Error;

    fn translate_update(self) -> Result<OnlyExistent<UU>, Self::Error> {
        match self {
            OnlyExistent(update) => update.translate_update().map(OnlyExistent),
        }
    }
}

/// Increase or decrease a counter.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Copy, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum IncOrDec {
    Inc(NonZeroU32),
    Dec(NonZeroU32),
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    None,
}

impl IncOrDec {
    pub const ONE: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };
}

impl IncOrDec {
    pub fn raw(&self) -> i64 {
        match self {
            Self::Inc(value) => value.get() as i64,
            Self::Dec(value) => -(value.get() as i64),
            Self::None => 0i64,
        }
    }
}

impl TranslateUpdate<IncOrDec> for AddOrRemoveOrModify<()> {
    type Error = Infallible;

    fn translate_update(self) -> Result<IncOrDec, Self::Error> {
        match self {
            Self::Add(()) => Ok(IncOrDec::Inc(IncOrDec::ONE)),
            Self::Remove => Ok(IncOrDec::Dec(IncOrDec::ONE)),
            Self::Modify(()) => Ok(IncOrDec::None),
        }
    }
}

impl<V> ApplyUpdate<Option<V>> for IncOrDec
where
    V: Deref<Target = NonZeroU32> + From<NonZeroU32>,
{
    fn apply_update(self, entity: &mut Option<V>) {
        match self {
            Self::Inc(inc) => match entity {
                Some(value) => {
                    *value = value
                        .checked_add(inc.get())
                        .map(Into::into)
                        .expect("Overflow")
                }
                None => {
                    entity.replace(inc.into());
                }
            },
            Self::Dec(dec) => {
                if entity.is_none() {
                    panic!("Attempt to decrement an absent counter")
                }

                *entity = entity
                    .take()
                    .map(|value| value.get().checked_sub(dec.get()).expect("Underflow"))
                    .and_then(NonZeroU32::new)
                    .map(V::from);
            }
            Self::None => {}
        }
    }
}

impl<A, V> ValidateUpdate<A, Option<V>> for IncOrDec
where
    V: Deref<Target = NonZeroU32> + From<NonZeroU32>,
    A: CanUpdate<V>,
{
    fn ensure_valid(&self, actor: &A, entity: &Option<V>) -> Result<(), UpdateError> {
        match self {
            Self::Inc(inc) => {
                let new = entity
                    .as_ref()
                    .map_or((*inc).into(), |value| value.checked_add(inc.get()))
                    .map(V::from)
                    .ok_or(UpdateError::Overflow)?;

                let cond = entity.as_ref().map_or_else(
                    || actor.can_add(&new),
                    |current| actor.can_replace(&new, current),
                );

                ensure!(cond, UpdateError::InvalidActor);
            }
            Self::Dec(dec) => {
                let current = entity.as_ref().ok_or(UpdateError::DoesntExist)?;
                let new = current
                    .get()
                    .checked_sub(dec.get())
                    .ok_or(UpdateError::Underflow)?;

                let cond = NonZeroU32::new(new).map_or_else(
                    || actor.can_remove(&current),
                    |new| actor.can_replace(&new.into(), &current),
                );

                ensure!(cond, UpdateError::InvalidActor);
            }
            Self::None => {}
        }

        Ok(())
    }
}

impl<V> GetUpdateKind<Option<V>> for IncOrDec
where
    V: Deref<Target = NonZeroU32> + From<NonZeroU32>,
{
    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        match self {
            Self::Inc(_) => entity
                .as_ref()
                .map_or(UpdateKind::Add, |_| UpdateKind::Replace),
            Self::Dec(_) => match entity.as_ref().map(Deref::deref) {
                Some(_) => UpdateKind::Remove,
                _ => UpdateKind::Replace,
            },
            Self::None => UpdateKind::None,
        }
    }
}

impl TranslateUpdate<IncOrDec> for IncOrDec {
    type Error = Infallible;

    fn translate_update(self) -> Result<Self, Self::Error> {
        Ok(self)
    }
}

impl CombineUpdates for IncOrDec {
    type Error = UpdateError;
    type Combined = Self;

    fn combine(self, other: Self) -> Result<IncOrDec, Self::Error> {
        let raw_ctr = self.raw() + other.raw();
        let abs_ctr_u32 = raw_ctr.abs().try_into();

        let res = if raw_ctr >= 0 {
            NonZeroU32::new(abs_ctr_u32.map_err(|_| UpdateError::Overflow)?)
                .map_or(IncOrDec::None, IncOrDec::Inc)
        } else {
            NonZeroU32::new(abs_ctr_u32.map_err(|_| UpdateError::Underflow)?)
                .map_or(IncOrDec::None, IncOrDec::Dec)
        };

        Ok(res)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum UpdateError {
    DoesntExist,
    AlreadyExists,
    InvalidActor,
    Overflow,
    Underflow,
    CapacityOverflow,
    ValidationFailed,
}

#[cfg(test)]
impl From<UpdateError> for DispatchError {
    fn from(error: UpdateError) -> Self {
        Self::Other(match error {
            UpdateError::Overflow => "An overflowed happened",
            UpdateError::Underflow => "An underflow happened",
            UpdateError::DoesntExist => "Entity doesn't exist",
            UpdateError::AlreadyExists => "Entity already exists",
            UpdateError::InvalidActor => "Provided actor can't perform this action",
            UpdateError::CapacityOverflow => "Capacity overflow",
            UpdateError::ValidationFailed => "Validation failed",
        })
    }
}

#[cfg(test)]
mod tests {
    use sp_runtime::{traits::ConstU32, BoundedBTreeMap};

    use crate::util::{ApplyUpdate, CanUpdate, CanUpdateKeyed, KeyValue, KeyedUpdate, UpdateError};

    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Map(BoundedBTreeMap<String, u8, ConstU32<5>>);
    crate::impl_wrapper!(Map(BoundedBTreeMap<String, u8, ConstU32<5>>));

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
    struct Counter(NonZeroU32);
    crate::impl_wrapper!(Counter(NonZeroU32));

    struct CanAddAndReplace;
    impl CanUpdateKeyed<Map> for CanAddAndReplace {
        fn can_update_keyed<U: crate::util::KeyedUpdate<Map>>(
            &self,
            _entity: &Map,
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

    struct CanAdd;
    impl CanUpdate<u8> for CanAdd {
        fn can_add(&self, _new: &u8) -> bool {
            true
        }
    }
    impl CanUpdate<Counter> for CanAdd {
        fn can_add(&self, _new: &Counter) -> bool {
            true
        }
    }

    struct CanRemove;
    impl CanUpdate<u8> for CanRemove {
        fn can_remove(&self, _entity: &u8) -> bool {
            true
        }
    }
    impl CanUpdate<Counter> for CanRemove {
        fn can_remove(&self, _new: &Counter) -> bool {
            true
        }
    }

    struct CanReplace;
    impl CanUpdate<u8> for CanReplace {
        fn can_replace(&self, _new: &u8, _current: &u8) -> bool {
            true
        }
    }
    impl CanUpdate<Counter> for CanReplace {
        fn can_replace(&self, _new: &Counter, _current: &Counter) -> bool {
            true
        }
    }

    struct CanDoEverything;
    impl CanUpdateKeyed<Map> for CanDoEverything {
        fn can_update_keyed<U: crate::util::KeyedUpdate<Map>>(
            &self,
            _entity: &Map,
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

        let mut entity = Map(BoundedBTreeMap::new());
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
        assert_eq!(update.kind(&cloned_entity), UpdateKind::Replace);

        update.apply_update(&mut cloned_entity);

        entity.try_insert("2".to_string(), 1).unwrap();

        assert_eq!(cloned_entity, entity);
    }

    #[test]
    fn inc_or_dec() {
        use IncOrDec::*;
        let one = IncOrDec::ONE;

        let mut value = Option::None::<Counter>;
        Inc(one).ensure_valid(&CanAdd, &value).unwrap();
        Inc(one).apply_update(&mut value);
        assert_eq!(value, Some(NonZeroU32::new(1).unwrap().into()));
        Inc(one).ensure_valid(&CanReplace, &value).unwrap();
        Inc(one).ensure_valid(&CanRemove, &value).unwrap_err();
        Inc(one).ensure_valid(&CanAdd, &value).unwrap_err();
        Inc(one).apply_update(&mut value);
        assert_eq!(value, Some(NonZeroU32::new(2).unwrap().into()));

        Dec(one).ensure_valid(&CanReplace, &value).unwrap();
        Dec(one).apply_update(&mut value);
        assert_eq!(value, Some(NonZeroU32::new(1).unwrap().into()));
        Dec(one).ensure_valid(&CanRemove, &value).unwrap();
        Dec(one).ensure_valid(&CanAdd, &value).unwrap_err();
        Dec(one).ensure_valid(&CanReplace, &value).unwrap_err();
        Dec(one).apply_update(&mut value);
        assert_eq!(value, Option::None);
        Dec(one).ensure_valid(&CanRemove, &value).unwrap_err();

        assert_eq!(Inc(one).combine(Dec(one)).unwrap(), None);
        assert_eq!(
            Inc(one).combine(Inc(one)).unwrap(),
            Inc(NonZeroU32::new(2).unwrap())
        );
        assert_eq!(
            Dec(one).combine(Dec(one)).unwrap(),
            Dec(NonZeroU32::new(2).unwrap())
        );
        assert_eq!(Dec(one).combine(Inc(one)).unwrap(), None);
    }

    #[test]
    fn multi_target_update_exceeding_capacity() {
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

        let mut entity = Map(BoundedBTreeMap::new());
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
        assert_eq!(update.kind(&entity), UpdateKind::Replace);

        update.apply_update(&mut entity);

        let mut new_entity = Map(BoundedBTreeMap::new());
        new_entity.try_insert("2".to_string(), 2).unwrap();
        new_entity.try_insert("4".to_string(), 4).unwrap();
        new_entity.try_insert("6".to_string(), 6).unwrap();
        new_entity.try_insert("8".to_string(), 8).unwrap();
        new_entity.try_insert("10".to_string(), 10).unwrap();

        assert_eq!(new_entity, entity);
    }

    #[test]
    fn set_or_add_or_remove_or_modify() {
        let mut value = Some(0);

        let set = SetOrAddOrRemoveOrModify::<u8, ()>::Set(10);

        assert_eq!(
            set.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(
            set.ensure_valid(&CanRemove, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(set.ensure_valid(&CanReplace, &value), Ok(()));
        assert_eq!(
            set.ensure_valid(&CanReplace, &None),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(set.ensure_valid(&CanAdd, &None), Ok(()));

        assert_eq!(set.kind(&value), UpdateKind::Replace);
        assert_eq!(set.kind(&None), UpdateKind::Add);

        set.apply_update(&mut value);
        assert_eq!(value, Some(10));

        let remove = SetOrAddOrRemoveOrModify::<u8, ()>::Remove;

        assert_eq!(
            remove.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(
            remove.ensure_valid(&CanReplace, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(remove.ensure_valid(&CanRemove, &value), Ok(()));
        assert_eq!(
            remove.ensure_valid(&CanReplace, &None),
            Err(UpdateError::DoesntExist)
        );
        assert_eq!(
            remove.ensure_valid(&CanRemove, &None),
            Err(UpdateError::DoesntExist)
        );

        assert_eq!(remove.kind(&value), UpdateKind::Remove);
        assert_eq!(remove.kind(&None), UpdateKind::None);

        remove.apply_update(&mut value);
        assert_eq!(value, None);

        let add = AddOrRemoveOrModify::<u8, ()>::Add(10);

        assert_eq!(
            add.ensure_valid(&CanAdd, &Some(5)),
            Err(UpdateError::AlreadyExists)
        );
        assert_eq!(
            add.ensure_valid(&CanReplace, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(add.ensure_valid(&CanAdd, &value), Ok(()));
        assert_eq!(
            add.ensure_valid(&CanReplace, &None),
            Err(UpdateError::InvalidActor)
        );

        assert_eq!(add.kind(&value), UpdateKind::Add);
        assert_eq!(add.kind(&Some(1)), UpdateKind::None);

        add.apply_update(&mut value);
        assert_eq!(value, Some(10));

        let modify =
            SetOrAddOrRemoveOrModify::<u8, _>::Modify(OnlyExistent(SetOrModify::<u8, ()>::Set(30)));

        assert_eq!(
            modify.ensure_valid(&CanAdd, &Some(5)),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(
            modify.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(modify.ensure_valid(&CanReplace, &value), Ok(()));
        assert_eq!(
            modify.ensure_valid(&CanRemove, &None),
            Err(UpdateError::DoesntExist)
        );

        assert_eq!(modify.kind(&value), UpdateKind::Replace);
        assert_eq!(modify.kind(&None), UpdateKind::None);

        modify.apply_update(&mut value);
        assert_eq!(value, Some(30));
    }

    #[test]
    fn add_or_remove_or_modify() {
        let mut value = Some(0);

        let remove = AddOrRemoveOrModify::<u8, ()>::Remove;

        assert_eq!(
            remove.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(
            remove.ensure_valid(&CanReplace, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(remove.ensure_valid(&CanRemove, &value), Ok(()));
        assert_eq!(
            remove.ensure_valid(&CanReplace, &None),
            Err(UpdateError::DoesntExist)
        );
        assert_eq!(
            remove.ensure_valid(&CanRemove, &None),
            Err(UpdateError::DoesntExist)
        );

        assert_eq!(remove.kind(&value), UpdateKind::Remove);
        assert_eq!(remove.kind(&None), UpdateKind::None);

        remove.apply_update(&mut value);
        assert_eq!(value, None);

        let add = AddOrRemoveOrModify::<u8, ()>::Add(10);

        assert_eq!(
            add.ensure_valid(&CanAdd, &Some(5)),
            Err(UpdateError::AlreadyExists)
        );
        assert_eq!(
            add.ensure_valid(&CanReplace, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(add.ensure_valid(&CanAdd, &value), Ok(()));
        assert_eq!(
            add.ensure_valid(&CanReplace, &None),
            Err(UpdateError::InvalidActor)
        );

        assert_eq!(add.kind(&value), UpdateKind::Add);
        assert_eq!(add.kind(&Some(1)), UpdateKind::None);

        add.apply_update(&mut value);
        assert_eq!(value, Some(10));

        let modify =
            SetOrAddOrRemoveOrModify::<u8, _>::Modify(OnlyExistent(SetOrModify::<u8, ()>::Set(30)));

        assert_eq!(
            modify.ensure_valid(&CanAdd, &Some(5)),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(
            modify.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(modify.ensure_valid(&CanReplace, &value), Ok(()));
        assert_eq!(
            modify.ensure_valid(&CanRemove, &None),
            Err(UpdateError::DoesntExist)
        );

        assert_eq!(modify.kind(&value), UpdateKind::Replace);
        assert_eq!(modify.kind(&None), UpdateKind::None);

        modify.apply_update(&mut value);
        assert_eq!(value, Some(30));
    }

    #[test]
    fn set_or_modify() {
        let mut value = 0;

        let set = SetOrModify::<u8, ()>::Set(10);

        assert_eq!(
            set.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(
            set.ensure_valid(&CanRemove, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(set.ensure_valid(&CanReplace, &value), Ok(()));
        assert_eq!(set.ensure_valid(&CanReplace, &value), Ok(()));
        assert_eq!(
            set.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );

        assert_eq!(set.kind(&value), UpdateKind::Replace);

        set.apply_update(&mut value);
        assert_eq!(value, 10);

        let modify = SetOrModify::<u8, _>::Modify(SetOrModify::<u8, ()>::Set(30));

        assert_eq!(
            modify.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(
            modify.ensure_valid(&CanAdd, &value),
            Err(UpdateError::InvalidActor)
        );
        assert_eq!(modify.ensure_valid(&CanReplace, &value), Ok(()));
        assert_eq!(
            modify.ensure_valid(&CanRemove, &value),
            Err(UpdateError::InvalidActor)
        );

        assert_eq!(modify.kind(&value), UpdateKind::Replace);

        modify.apply_update(&mut value);
        assert_eq!(value, 30);
    }
}
