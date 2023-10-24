use super::BoundedKeyValue;
use alloc::collections::{BTreeMap, BTreeSet};
use codec::{Decode, Encode, MaxEncodedLen};
use core::ops::DerefMut;
use frame_support::*;
use sp_runtime::{DispatchError, Either};

/// Checks whether an actor can update an entity.
pub trait CanUpdate<Entity>: Sized {
    #[must_use]
    fn can_add(&self, _new: &Entity) -> bool {
        false
    }

    #[must_use]
    fn can_replace(&self, _new: &Entity, _current: &Entity) -> bool {
        false
    }

    #[must_use]
    fn can_remove(&self, _entity: &Entity) -> bool {
        false
    }
}

/// Checks whether an actor can update an entity over some keys.
pub trait CanUpdateKeyed<Entity>
where
    Entity: core::ops::Deref,
    Entity::Target: BoundedKeyValue,
{
    #[must_use]
    fn can_update_keyed<U: KeyedUpdate<Entity>>(&self, _entity: &Entity, _update: &U) -> bool {
        false
    }
}

/// Checks whether an actor can either update a whole entity or some of its keys.
pub trait CanUpdateAndCanUpdateKeyed<Entity>: CanUpdateKeyed<Entity> + CanUpdate<Entity>
where
    Entity: core::ops::Deref,
    Entity::Target: BoundedKeyValue,
{
}
impl<Entity, T: CanUpdateKeyed<Entity> + CanUpdate<Entity>> CanUpdateAndCanUpdateKeyed<Entity> for T
where
    Entity: core::ops::Deref,
    Entity::Target: BoundedKeyValue,
{
}

/// Applies an update to the entity.
pub trait ApplyUpdate<Entity> {
    type Output<'output>
    where
        Entity: 'output;

    fn apply_update(self, entity: &mut Entity) -> Self::Output<'_>;

    fn kind(&self, entity: &Entity) -> UpdateKind;
}

pub trait ValidateUpdate<Actor, Entity>: ApplyUpdate<Entity> {
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

pub trait KeyedUpdate<Entity: core::ops::Deref>
where
    Entity::Target: BoundedKeyValue,
{
    type Targets<'a>: Iterator<Item = &'a <Entity::Target as BoundedKeyValue>::Key> + 'a
    where
        Self: 'a,
        <Entity::Target as BoundedKeyValue>::Key: 'a,
        Entity: 'a;

    fn targets<'targets>(&'targets self, entity: &'targets Entity) -> Self::Targets<'targets>;

    fn key_diff(
        &self,
        entity: &Entity,
    ) -> MultiTargetUpdate<<Entity::Target as BoundedKeyValue>::Key, AddOrRemoveOrModify<()>>;
}

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

crate::impl_wrapper!(MultiTargetUpdate<K, U> where K: Ord => (BTreeMap<K, U>));

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
    type Output<'output> = () where V: 'output;

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
    type Output<'output> = U::Output<'output> where Option<V>: 'output;

    fn apply_update(self, entity: &mut Option<V>) -> Self::Output<'_> {
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

impl<V, U: ApplyUpdate<Option<V>>> ApplyUpdate<Option<V>> for AddOrRemoveOrModify<V, U> {
    type Output<'output> = () where Option<V>: 'output;

    fn apply_update(self, entity: &mut Option<V>) {
        match self {
            AddOrRemoveOrModify::Add(value) => {
                entity.replace(value);
            }
            AddOrRemoveOrModify::Remove => {
                entity.take();
            }
            AddOrRemoveOrModify::Modify(update) => {
                update.apply_update(entity);
            }
        }
    }

    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        match self {
            AddOrRemoveOrModify::Add(_) => {
                if entity.is_none() {
                    UpdateKind::Add
                } else {
                    UpdateKind::Replace
                }
            }
            AddOrRemoveOrModify::Remove => {
                if entity.is_some() {
                    UpdateKind::Remove
                } else {
                    UpdateKind::None
                }
            }
            AddOrRemoveOrModify::Modify(update) => update.kind(entity),
        }
    }
}

impl<A: CanUpdate<V>, V, U: ValidateUpdate<A, Option<V>>> ValidateUpdate<A, Option<V>>
    for AddOrRemoveOrModify<V, U>
{
    fn ensure_valid(&self, actor: &A, entity: &Option<V>) -> Result<(), UpdateError> {
        match self {
            AddOrRemoveOrModify::Add(value) => {
                ensure!(entity.is_none(), UpdateError::AlreadyExists);
                ensure!(actor.can_add(value), UpdateError::InvalidActor);
            }
            AddOrRemoveOrModify::Remove => {
                let existing = entity.as_ref().ok_or(UpdateError::DoesntExist)?;

                ensure!(actor.can_remove(existing), UpdateError::InvalidActor);
            }
            AddOrRemoveOrModify::Modify(update) => return update.ensure_valid(actor, entity),
        };

        Ok(())
    }
}

impl<V, U: ApplyUpdate<Option<V>>> ApplyUpdate<Option<V>> for SetOrModify<V, U> {
    type Output<'output> = Option<U::Output<'output>> where Option<V>: 'output;

    fn apply_update(self, entity: &mut Option<V>) -> Self::Output<'_> {
        match self {
            SetOrModify::Set(value) => {
                entity.replace(value);
                None
            }
            SetOrModify::Modify(update) => Some(update.apply_update(entity)),
        }
    }

    fn kind(&self, entity: &Option<V>) -> UpdateKind {
        match self {
            SetOrModify::Set(_) => match entity {
                Some(_) => UpdateKind::Replace,
                None => UpdateKind::Add,
            },
            SetOrModify::Modify(update) => update.kind(entity),
        }
    }
}

impl<A: CanUpdate<V>, V, U: ValidateUpdate<A, Option<V>>> ValidateUpdate<A, Option<V>>
    for SetOrModify<V, U>
{
    fn ensure_valid(&self, actor: &A, entity: &Option<V>) -> Result<(), UpdateError> {
        match self {
            SetOrModify::Set(new) => {
                let cond = match entity {
                    Some(current) => actor.can_replace(new, current),
                    None => actor.can_add(new),
                };

                ensure!(cond, UpdateError::InvalidActor);

                Ok(())
            }
            SetOrModify::Modify(update) => update.ensure_valid(actor, entity),
        }
    }
}

impl<V, U: ApplyUpdate<V>> ApplyUpdate<V> for SetOrModify<V, U> {
    type Output<'output> = Option<U::Output<'output>> where V: 'output;

    fn apply_update(self, entity: &mut V) -> Self::Output<'_> {
        match self {
            SetOrModify::Set(value) => {
                *entity = value;
                None
            }
            SetOrModify::Modify(update) => Some(update.apply_update(entity)),
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
    type Output<'output> = () where C: 'output;

    fn apply_update(self, entity: &mut C) -> Self::Output<'_> {
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

    fn key_diff(
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

    fn key_diff(
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
            Self::Modify(update) => update.key_diff(entity),
        }
    }
}
