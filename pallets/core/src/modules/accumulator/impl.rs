use super::*;
use crate::deposit_indexed_event;

impl<T: Config> Pallet<T> {
    pub(super) fn add_params_(
        AddAccumulatorParams { params, .. }: AddAccumulatorParams<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        let params_counter =
            AccumulatorOwnerCounters::<T>::mutate(owner, |counters| *counters.params_counter.inc());
        AccumulatorParams::<T>::insert(owner, params_counter, params);

        Self::deposit_event(Event::ParamsAdded(owner, params_counter));
        Ok(())
    }

    pub(super) fn add_public_key_(
        AddAccumulatorPublicKey { public_key, .. }: AddAccumulatorPublicKey<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        if let Some((acc_owner, params_id)) = public_key.params_ref {
            ensure!(
                AccumulatorParams::<T>::contains_key(acc_owner, params_id),
                Error::<T>::ParamsDontExist
            );
        }

        let keys_counter =
            AccumulatorOwnerCounters::<T>::mutate(owner, |counters| *counters.key_counter.inc());
        AccumulatorKeys::insert(owner, keys_counter, public_key);

        Self::deposit_event(Event::KeyAdded(owner, keys_counter));
        Ok(())
    }

    pub(super) fn remove_params_(
        RemoveAccumulatorParams {
            params_ref: (did, counter),
            ..
        }: RemoveAccumulatorParams<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        // Only the DID that added the param can remove it
        ensure!(did == owner, Error::<T>::NotAccumulatorOwner);
        ensure!(
            AccumulatorParams::<T>::contains_key(did, counter),
            Error::<T>::ParamsDontExist
        );

        AccumulatorParams::<T>::remove(did, counter);

        Self::deposit_event(Event::ParamsRemoved(did, counter));
        Ok(())
    }

    pub(super) fn remove_public_key_(
        RemoveAccumulatorPublicKey {
            key_ref: (did, counter),
            ..
        }: RemoveAccumulatorPublicKey<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        ensure!(did == owner, Error::<T>::NotAccumulatorOwner);
        ensure!(
            AccumulatorKeys::<T>::contains_key(did, counter),
            Error::<T>::PublicKeyDoesntExist
        );

        AccumulatorKeys::<T>::remove(did, counter);

        Self::deposit_event(Event::KeyRemoved(did, counter));
        Ok(())
    }

    pub(super) fn add_accumulator_(
        AddAccumulator {
            id, accumulator, ..
        }: AddAccumulator<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        ensure!(
            !Accumulators::<T>::contains_key(id),
            Error::<T>::AccumulatorAlreadyExists
        );

        let (acc_owner, key_id) = accumulator.key_ref();
        ensure!(
            AccumulatorKeys::<T>::contains_key(acc_owner, key_id),
            Error::<T>::PublicKeyDoesntExist
        );
        ensure!(acc_owner == owner, Error::<T>::NotPublicKeyOwner);

        let accumulated = accumulator.accumulated().to_vec().into();

        let current_block = <frame_system::Pallet<T>>::block_number();
        Accumulators::<T>::insert(
            id,
            AccumulatorWithUpdateInfo::new(accumulator, current_block),
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
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        Accumulators::<T>::try_mutate(id, |accumulator| -> DispatchResult {
            let accumulator = accumulator
                .as_mut()
                .ok_or(Error::<T>::AccumulatorDoesntExist)?;

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

            Ok(())
        })?;

        // The event stores only the accumulated value which can be used by the verifier.
        // For witness update, that information is retrieved by looking at the block and parsing the extrinsic.
        deposit_indexed_event!(AccumulatorUpdated(id, new_accumulated) over id);
        Ok(())
    }

    pub(super) fn remove_accumulator_(
        RemoveAccumulator { id, .. }: RemoveAccumulator<T>,
        signer: AccumulatorOwner,
    ) -> DispatchResult {
        let accumulator = Accumulators::<T>::get(id).ok_or(Error::<T>::AccumulatorDoesntExist)?;

        // Only the DID that added the accumulator can remove it
        ensure!(
            *accumulator.accumulator.owner_did() == signer,
            Error::<T>::NotAccumulatorOwner
        );
        Accumulators::<T>::remove(id);

        deposit_indexed_event!(AccumulatorRemoved(id));
        Ok(())
    }

    pub fn public_key_with_params(
        (key_did, key_id): &AccumPublicKeyStorageKey,
    ) -> Option<AccumPublicKeyWithParams<T>> {
        let pk = AccumulatorKeys::get(key_did, key_id)?;
        let params = match &pk.params_ref {
            Some((params_did, params_id)) => AccumulatorParams::<T>::get(params_did, params_id),
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
