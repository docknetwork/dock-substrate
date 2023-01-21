use super::*;

impl<T: Config + Debug> Module<T> {
    pub(super) fn add_params_(
        AddBBSPlusParams { params, .. }: AddBBSPlusParams<T>,
        signer: BBSPlusParamsOwner,
    ) -> DispatchResult {
        ensure!(
            T::LabelMaxSize::get() as usize >= params.label.as_ref().map_or(0, |l| l.len()),
            Error::<T>::LabelTooBig
        );
        ensure!(
            T::ParamsMaxSize::get() as usize >= params.bytes.len(),
            Error::<T>::ParamsTooBig
        );

        let params_count = ParamsCounter::mutate(signer, |counter| *counter.inc());
        BbsPlusParams::insert(signer, params_count, params);

        Self::deposit_event(Event::ParamsAdded(signer, params_count));
        Ok(())
    }

    pub(super) fn add_public_key_(
        AddBBSPlusPublicKey {
            did: owner, key, ..
        }: AddBBSPlusPublicKey<T>,
        OnChainDidDetails { last_key_id, .. }: &mut OnChainDidDetails,
    ) -> DispatchResult {
        ensure!(
            T::PublicKeyMaxSize::get() as usize >= key.bytes.len(),
            Error::<T>::PublicKeyTooBig
        );
        if let Some((did, counter)) = key.params_ref {
            ensure!(
                BbsPlusParams::contains_key(&did, &counter),
                Error::<T>::ParamsDontExist
            );
            // Note: Once we have more than 1 curve type, it should check that params and key
            // both have same curve type
        };
        BbsPlusKeys::insert(owner, last_key_id.inc(), key);

        Self::deposit_event(Event::KeyAdded(owner, *last_key_id));
        Ok(())
    }

    pub(super) fn remove_params_(
        RemoveBBSPlusParams {
            params_ref: (did, counter),
            ..
        }: RemoveBBSPlusParams<T>,
        owner: BBSPlusParamsOwner,
    ) -> DispatchResult {
        // Only the DID that added the param can it
        ensure!(did == owner, Error::<T>::NotOwner);

        ensure!(
            BbsPlusParams::contains_key(&did, &counter),
            Error::<T>::ParamsDontExist
        );

        BbsPlusParams::remove(&did, &counter);

        Self::deposit_event(Event::ParamsRemoved(did, counter));
        Ok(())
    }

    pub(super) fn remove_public_key_(
        RemoveBBSPlusPublicKey {
            key_ref: (did, counter),
            did: owner,
            ..
        }: RemoveBBSPlusPublicKey<T>,
        _: &mut OnChainDidDetails,
    ) -> DispatchResult {
        ensure!(
            BbsPlusKeys::contains_key(&did, &counter),
            Error::<T>::PublicKeyDoesntExist
        );

        ensure!(did == owner, Error::<T>::NotOwner);

        BbsPlusKeys::remove(&did, &counter);

        Self::deposit_event(Event::KeyRemoved(did, counter));
        Ok(())
    }

    pub fn get_public_key_with_params(
        key_ref: &BBSPlusPublicKeyStorageKey,
    ) -> Option<BBSPlusPublicKeyWithParams> {
        BbsPlusKeys::get(&key_ref.0, &key_ref.1).map(|pk| {
            let params = pk.params_ref.and_then(|r| BbsPlusParams::get(r.0, r.1));

            (pk, params)
        })
    }

    pub fn get_params_by_did(id: &BBSPlusParamsOwner) -> BTreeMap<IncId, BBSPlusParameters> {
        let mut params = BTreeMap::new();
        for (idx, val) in BbsPlusParams::iter_prefix(*id) {
            params.insert(idx, val);
        }
        params
    }

    pub fn get_public_key_by_did(id: &Did) -> BTreeMap<IncId, BBSPlusPublicKeyWithParams> {
        let mut keys = BTreeMap::new();
        for (idx, pk) in BbsPlusKeys::iter_prefix(id) {
            let params = pk.params_ref.and_then(|r| BbsPlusParams::get(r.0, r.1));

            keys.insert(idx, (pk, params));
        }
        keys
    }
}
