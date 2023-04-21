use crate::{
    did::{Did, OnChainDidDetails},
    offchain_signatures::{schemas::*, SignatureParams},
    util::IncId,
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{ensure, traits::Get, IterableStorageDoubleMap, StorageDoubleMap};
use sp_runtime::DispatchResult;

use super::{
    AddOffchainSignaturePublicKey, Config, Error, Event, Module, OffchainSignatureParams,
    PublicKeys, RemoveOffchainSignaturePublicKey, SignatureParamsStorageKey,
};

pub type SignaturePublicKeyStorageKey = (Did, IncId);

/// Public key for different signature schemes. Currently can be either BBS+ or Pointcheval-Sanders.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum OffchainPublicKey {
    /// Public key for the BBS signature scheme.
    BBS(BBSPublicKey),
    /// Public key for the BBS+ signature scheme.
    BBSPlus(BBSPlusPublicKey),
    /// Public key for the Pointcheval-Sanders signature scheme.
    PS(PSPublicKey),
}

impl OffchainPublicKey {
    /// Returns underlying public key if it corresponds to the BBS+ scheme.
    pub fn into_bbs(self) -> Option<BBSPublicKey> {
        self.try_into().ok()
    }

    /// Returns underlying public key if it corresponds to the BBS+ scheme.
    pub fn into_bbs_plus(self) -> Option<BBSPlusPublicKey> {
        self.try_into().ok()
    }

    /// Returns underlying public key if it corresponds to the Pointcheval-Sanders scheme.
    pub fn into_ps(self) -> Option<PSPublicKey> {
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
    pub fn params_match_scheme(&self, params: &OffchainSignatureParams) -> bool {
        match self {
            Self::BBS(_) => matches!(params, OffchainSignatureParams::BBS(_)),
            Self::BBSPlus(_) => matches!(params, OffchainSignatureParams::BBSPlus(_)),
            Self::PS(_) => matches!(params, OffchainSignatureParams::PS(_)),
        }
    }

    /// Ensures that supplied key has a valid size and has constrained parameters.
    pub fn ensure_valid<T: Config + Debug>(&self) -> Result<(), Error<T>> {
        ensure!(
            T::PublicKeyMaxSize::get() as usize >= self.bytes().len(),
            Error::<T>::PublicKeyTooBig
        );
        if let Some((did, params_id)) = self.params_ref() {
            let params = SignatureParams::get(did, params_id).ok_or(Error::<T>::ParamsDontExist)?;

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

impl<T: Config + Debug> Module<T> {
    pub(super) fn add_public_key_(
        AddOffchainSignaturePublicKey {
            did: owner, key, ..
        }: AddOffchainSignaturePublicKey<T>,
        OnChainDidDetails { last_key_id, .. }: &mut OnChainDidDetails,
    ) -> DispatchResult {
        key.ensure_valid::<T>()?;

        PublicKeys::insert(owner, last_key_id.inc(), key);

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
            PublicKeys::contains_key(did, counter),
            Error::<T>::PublicKeyDoesntExist
        );

        ensure!(did == owner, Error::<T>::NotOwner);

        PublicKeys::remove(did, counter);

        Self::deposit_event(Event::KeyRemoved(owner, counter));
        Ok(())
    }

    pub fn did_public_keys(did: &Did) -> impl Iterator<Item = (IncId, OffchainPublicKey)> {
        PublicKeys::iter_prefix(did)
    }
}
