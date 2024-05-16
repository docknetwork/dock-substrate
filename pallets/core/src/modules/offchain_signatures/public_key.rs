use crate::{
    common::Limits,
    did::{Did, OnChainDidDetails},
    offchain_signatures::{schemes::*, SignatureParams},
    util::IncId,
};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{ensure, DebugNoBound};
use sp_runtime::DispatchResult;

use super::{
    AddOffchainSignaturePublicKey, Config, Error, Event, OffchainSignatureParams, Pallet,
    PublicKeys, RemoveOffchainSignaturePublicKey, SignatureParamsStorageKey,
};

pub type SignaturePublicKeyStorageKey = (Did, IncId);

/// Public key for different signature schemes. Currently can be either `BBS`, `BBS+` or `Pointcheval-Sanders`.
#[derive(
    scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub enum OffchainPublicKey<T: Limits> {
    /// Public key for the BBS signature scheme.
    BBS(BBSPublicKey<T>),
    /// Public key for the BBS+ signature scheme.
    BBSPlus(BBSPlusPublicKey<T>),
    /// Public key for the Pointcheval-Sanders signature scheme.
    PS(PSPublicKey<T>),
}

impl<T: Limits> OffchainPublicKey<T> {
    /// Returns underlying public key if it corresponds to the BBS scheme.
    pub fn into_bbs(self) -> Option<BBSPublicKey<T>> {
        self.try_into().ok()
    }

    /// Returns underlying public key if it corresponds to the BBS+ scheme.
    pub fn into_bbs_plus(self) -> Option<BBSPlusPublicKey<T>> {
        self.try_into().ok()
    }

    /// Returns underlying public key if it corresponds to the Pointcheval-Sanders scheme.
    pub fn into_ps(self) -> Option<PSPublicKey<T>> {
        self.try_into().ok()
    }

    /// Returns underlying **unchecked** bytes representation for a key corresponding to either signature scheme.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::BBS(key) => &key.bytes[..],
            Self::BBSPlus(key) => &key.bytes[..],
            Self::PS(key) => &key.bytes[..],
        }
    }

    /// Returns underlying parameters reference for a key corresponding to either signature scheme.
    pub fn params_ref(&self) -> Option<&SignatureParamsStorageKey> {
        let opt = match self {
            Self::BBS(bbs_key) => &bbs_key.params_ref,
            Self::BBSPlus(bbs_plus_key) => &bbs_plus_key.params_ref,
            Self::PS(ps_key) => &ps_key.params_ref,
        };

        opt.as_ref()
    }

    /// Returns `true` if supplied params have same scheme as the given key.
    pub fn params_match_scheme(&self, params: &OffchainSignatureParams<T>) -> bool {
        match self {
            Self::BBS(_) => matches!(params, OffchainSignatureParams::BBS(_)),
            Self::BBSPlus(_) => matches!(params, OffchainSignatureParams::BBSPlus(_)),
            Self::PS(_) => matches!(params, OffchainSignatureParams::PS(_)),
        }
    }

    /// Ensures that supplied key has a valid size and has constrained parameters.
    pub fn ensure_valid(&self) -> Result<(), Error<T>>
    where
        T: Config,
    {
        if let Some((did, params_id)) = self.params_ref() {
            let params =
                SignatureParams::<T>::get(did, params_id).ok_or(Error::<T>::ParamsDontExist)?;

            ensure!(
                self.params_match_scheme(&params),
                Error::<T>::IncorrectParamsScheme
            );
            // Note: Once we have more than 1 curve type, it should check that params and key
            // both have same curve type
        };

        Ok(())
    }
}

impl<T: Config> Pallet<T> {
    pub(super) fn add_public_key_(
        AddOffchainSignaturePublicKey {
            did: owner, key, ..
        }: AddOffchainSignaturePublicKey<T>,
        OnChainDidDetails { last_key_id, .. }: &mut OnChainDidDetails,
    ) -> DispatchResult {
        key.ensure_valid()?;

        PublicKeys::<T>::insert(owner, last_key_id.inc(), key);

        Self::deposit_event(Event::KeyAdded(owner, *last_key_id));
        Ok(())
    }

    pub(super) fn remove_public_key_(
        RemoveOffchainSignaturePublicKey {
            key_ref: (did, counter),
            did: owner,
            ..
        }: RemoveOffchainSignaturePublicKey<T>,
        _: &mut OnChainDidDetails,
    ) -> DispatchResult {
        ensure!(
            PublicKeys::<T>::contains_key(did, counter),
            Error::<T>::PublicKeyDoesntExist
        );

        ensure!(did == owner, Error::<T>::NotOwner);

        PublicKeys::<T>::remove(did, counter);

        Self::deposit_event(Event::KeyRemoved(owner, counter));
        Ok(())
    }

    pub fn did_public_keys(did: &Did) -> impl Iterator<Item = (IncId, OffchainPublicKey<T>)> {
        PublicKeys::<T>::iter_prefix(did)
    }
}
