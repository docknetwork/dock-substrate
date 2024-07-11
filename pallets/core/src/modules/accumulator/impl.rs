use super::*;
use crate::deposit_indexed_event;

impl<T: Config> Pallet<T> {
    pub(super) fn add_params_(
        AddAccumulatorParams { params, .. }: AddAccumulatorParams<T>,
        StoredAccumulatorOwnerCounters { params_counter, .. }: &mut StoredAccumulatorOwnerCounters,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        AccumulatorParams::<T>::insert(owner, params_counter.inc(), params);

        Self::deposit_event(Event::ParamsAdded(owner, *params_counter));
        Ok(())
    }

    pub(super) fn add_public_key_(
        AddAccumulatorPublicKey { public_key, .. }: AddAccumulatorPublicKey<T>,
        StoredAccumulatorOwnerCounters { key_counter, .. }: &mut StoredAccumulatorOwnerCounters,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        if let Some(AccumParametersStorageKey(acc_owner, params_id)) = public_key.params_ref {
            ensure!(
                AccumulatorParams::<T>::contains_key(acc_owner, params_id),
                Error::<T>::ParamsDontExist
            );
        }

        AccumulatorKeys::insert(owner, key_counter.inc(), public_key);

        Self::deposit_event(Event::KeyAdded(owner, *key_counter));
        Ok(())
    }

    pub(super) fn remove_params_(
        RemoveAccumulatorParams {
            params_ref: AccumParametersStorageKey(did, counter),
            ..
        }: RemoveAccumulatorParams<T>,
        accumulator_params: &mut Option<AccumulatorParameters<T>>,
        _: AccumulatorOwner,
    ) -> DispatchResult {
        accumulator_params
            .take()
            .ok_or(Error::<T>::ParamsDontExist)?;

        Self::deposit_event(Event::ParamsRemoved(did, counter));
        Ok(())
    }

    pub(super) fn remove_public_key_(
        RemoveAccumulatorPublicKey {
            key_ref: AccumPublicKeyStorageKey(did, counter),
            ..
        }: RemoveAccumulatorPublicKey<T>,
        accumulator_pk: &mut Option<AccumulatorPublicKey<T>>,
        _: AccumulatorOwner,
    ) -> DispatchResult {
        accumulator_pk
            .take()
            .ok_or(Error::<T>::PublicKeyDoesntExist)?;

        Self::deposit_event(Event::KeyRemoved(did, counter));
        Ok(())
    }

    pub(super) fn add_accumulator_(
        AddAccumulator {
            id, accumulator, ..
        }: AddAccumulator<T>,
        acc_opt: &mut Option<AccumulatorWithUpdateInfo<T>>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        let AccumPublicKeyStorageKey(acc_owner, key_id) = accumulator.key_ref();

        // key_id being zero indicates that no public key exists for the accumulator and this is acceptable
        // in certain cases, like when using KVAC
        if !key_id.is_zero() {
            ensure!(
                AccumulatorKeys::<T>::contains_key(acc_owner, key_id),
                Error::<T>::PublicKeyDoesntExist
            );
        }

        ensure!(acc_owner == owner, Error::<T>::NotPublicKeyOwner);

        let accumulated = accumulator.accumulated().to_vec().into();

        let current_block = <frame_system::Pallet<T>>::block_number();
        let acc = AccumulatorWithUpdateInfo::new(accumulator, current_block);
        ensure!(
            acc_opt.replace(acc).is_none(),
            Error::<T>::AccumulatorAlreadyExists
        );

        deposit_indexed_event!(AccumulatorAdded(id, accumulated) over id);
        Ok(())
    }

    pub(super) fn update_accumulator_(
        UpdateAccumulator {
            id,
            new_accumulated,
            ..
        }: UpdateAccumulator<T>,
        accumulator: &mut AccumulatorWithUpdateInfo<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        // Only the DID that added the accumulator can update it
        ensure!(
            *accumulator.accumulator.owner_did() == owner,
            Error::<T>::NotAccumulatorOwner
        );

        accumulator
            .accumulator
            .set_new_accumulated(new_accumulated.clone().0)
            .map_err(|_| Error::<T>::AccumulatedTooBig)?;
        accumulator.last_updated_at = <frame_system::Pallet<T>>::block_number();

        // The event stores only the accumulated value which can be used by the verifier.
        // For witness update, that information is retrieved by looking at the block and parsing the extrinsic.
        deposit_indexed_event!(AccumulatorUpdated(id, new_accumulated) over id);
        Ok(())
    }

    pub(super) fn remove_accumulator_(
        RemoveAccumulator { id, .. }: RemoveAccumulator<T>,
        accumulator: &mut Option<AccumulatorWithUpdateInfo<T>>,
        signer: AccumulatorOwner,
    ) -> DispatchResult {
        let accumulator = accumulator
            .take()
            .ok_or(Error::<T>::AccumulatorDoesntExist)?;

        // Only the DID that added the accumulator can remove it
        ensure!(
            *accumulator.accumulator.owner_did() == signer,
            Error::<T>::NotAccumulatorOwner
        );

        deposit_indexed_event!(AccumulatorRemoved(id));
        Ok(())
    }

    pub fn public_key_with_params(
        AccumPublicKeyStorageKey(key_did, key_id): &AccumPublicKeyStorageKey,
    ) -> Option<AccumPublicKeyWithParams<T>> {
        let pk = AccumulatorKeys::get(key_did, key_id)?;
        let params = match &pk.params_ref {
            Some(AccumParametersStorageKey(params_did, params_id)) => {
                AccumulatorParams::<T>::get(params_did, params_id)
            }
            _ => None,
        };

        Some((pk, params))
    }

    /// Get accumulated value with public key and params.
    pub fn get_accumulator_with_public_key_and_params(
        id: &AccumulatorId,
    ) -> Option<(Vec<u8>, Option<AccumPublicKeyWithParams<T>>)> {
        let stored_acc = Accumulators::<T>::get(id)?;
        let pk_p = Self::public_key_with_params(&stored_acc.accumulator.key_ref());

        Some((stored_acc.accumulator.accumulated().to_vec(), pk_p))
    }
}
