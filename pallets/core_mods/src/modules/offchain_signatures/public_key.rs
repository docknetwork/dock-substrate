use crate::{
    did::{Did, OnChainDidDetails},
    offchain_signatures::SignatureParams,
    types::CurveType,
    util::{Bytes, IncId},
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{ensure, traits::Get, IterableStorageDoubleMap, StorageDoubleMap};
use sp_runtime::DispatchResult;

use super::{
    AddOffchainSignaturePublicKey, BBSPlusPublicKeyWithParams, Config, Error, Event, Module,
    OffchainSignatureParams, OffchainSignatureParamsStorageKey, PSPublicKeyWithParams, PublicKeys,
    RemoveOffchainSignaturePublicKey,
};

pub type SignaturePublicKeyStorageKey = (Did, IncId);

/// Public key for different signature schemes. Currently can be either BBS+ or Pointcheval-Sanders.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum OffchainPublicKey {
    /// Public key for the BBS+ signature scheme.
    BBSPlus(BBSPlusPublicKey),
    /// Public key for the Pointcheval-Sanders signature scheme.
    PS(PSPublicKey),
}

impl OffchainPublicKey {
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
            Self::BBSPlus(params) => &params.bytes[..],
            Self::PS(params) => &params.bytes[..],
        }
    }

    /// Returns underlying parameters reference for a key corresponding to either signature scheme.
    pub fn params_ref(&self) -> Option<&OffchainSignatureParamsStorageKey> {
        let opt = match self {
            Self::BBSPlus(bbs_plus_key) => &bbs_plus_key.params_ref,
            Self::PS(ps_key) => &ps_key.params_ref,
        };

        opt.as_ref()
    }

    /// Returns `true` if supplied params have same scheme as the given key.
    pub fn params_match_scheme(&self, params: &OffchainSignatureParams) -> bool {
        match self {
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

/// Public key for the BBS+ signature scheme.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct BBSPlusPublicKey(OffchainPublicKeyBase);
crate::impl_wrapper! { no_wrapper_from_type BBSPlusPublicKey(OffchainPublicKeyBase) }

/// Public key for the Pointcheval-Sanders signature scheme.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct PSPublicKey(OffchainPublicKeyBase);
crate::impl_wrapper! { no_wrapper_from_type PSPublicKey(OffchainPublicKeyBase) }

impl BBSPlusPublicKey {
    /// Instantiates new public key for the BBS+ signature scheme.
    /// This function doesn't validate supplied bytes.
    pub fn new(
        bytes: impl Into<Bytes>,
        params_ref: impl Into<Option<OffchainSignatureParamsStorageKey>>,
        curve_type: CurveType,
    ) -> Self {
        Self(OffchainPublicKeyBase {
            bytes: bytes.into(),
            params_ref: params_ref.into(),
            curve_type,
            participant_id: None,
        })
    }

    /// Instantiates new public key with participant id for the BBS+ signature scheme.
    /// This function doesn't validate supplied bytes.
    /// Participant id implies the usage of this key in threshold issuance.
    pub fn new_participant(
        bytes: impl Into<Bytes>,
        params_ref: impl Into<Option<OffchainSignatureParamsStorageKey>>,
        curve_type: CurveType,
        participant_id: u16,
    ) -> Self {
        let mut this = Self::new(bytes, params_ref, curve_type);
        this.participant_id = Some(participant_id);

        this
    }

    /// Combines BBS+ key with signature params (if exist and have BBS+ scheme).
    pub fn with_params(self) -> BBSPlusPublicKeyWithParams {
        let params = self
            .params_ref
            .as_ref()
            .and_then(|(did, params_id)| SignatureParams::get(did, params_id))
            .and_then(OffchainSignatureParams::into_bbs_plus);

        (self, params)
    }
}

impl PSPublicKey {
    /// Instantiates new public key for the Pointcheval-Sanders signature scheme.
    /// This function doesn't validate supplied bytes.
    pub fn new(
        bytes: impl Into<Bytes>,
        params_ref: impl Into<Option<OffchainSignatureParamsStorageKey>>,
        curve_type: CurveType,
    ) -> Self {
        Self(OffchainPublicKeyBase {
            bytes: bytes.into(),
            params_ref: params_ref.into(),
            curve_type,
            participant_id: None,
        })
    }

    /// Instantiates new public key with participant id for the BBS+ signature scheme.
    /// This function doesn't validate supplied bytes.
    /// Participant id implies the usage of this key in threshold issuance.
    pub fn new_participant(
        bytes: impl Into<Bytes>,
        params_ref: impl Into<Option<OffchainSignatureParamsStorageKey>>,
        curve_type: CurveType,
        participant_id: u16,
    ) -> Self {
        let mut this = Self::new(bytes, params_ref, curve_type);
        this.participant_id = Some(participant_id);

        this
    }

    /// Combines Pointcheval-Sanders key with signature params (if exist and have Pointcheval-Sanders scheme).
    pub fn with_params(self) -> PSPublicKeyWithParams {
        let params = self
            .params_ref
            .as_ref()
            .and_then(|(did, params_id)| SignatureParams::get(did, params_id))
            .and_then(OffchainSignatureParams::into_ps);

        (self, params)
    }
}

impl TryFrom<OffchainPublicKey> for BBSPlusPublicKey {
    type Error = OffchainPublicKey;

    fn try_from(key: OffchainPublicKey) -> Result<Self, OffchainPublicKey> {
        match key {
            OffchainPublicKey::BBSPlus(key) => Ok(key),
            other => Err(other),
        }
    }
}

impl TryFrom<OffchainPublicKey> for PSPublicKey {
    type Error = OffchainPublicKey;

    fn try_from(key: OffchainPublicKey) -> Result<Self, OffchainPublicKey> {
        match key {
            OffchainPublicKey::PS(key) => Ok(key),
            other => Err(other),
        }
    }
}

/// Defines shared base for the offchain signature public key. Can be changed later.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct OffchainPublicKeyBase {
    /// The public key should be for the same curve as the parameters but a public key might not have
    /// parameters on chain
    pub curve_type: CurveType,
    pub bytes: Bytes,
    /// The params used to generate the public key
    pub params_ref: Option<OffchainSignatureParamsStorageKey>,
    /// Optional participant id used in threshold issuance.
    pub participant_id: Option<u16>,
}

impl From<BBSPlusPublicKey> for OffchainPublicKey {
    fn from(bbs_plus_key: BBSPlusPublicKey) -> Self {
        Self::BBSPlus(bbs_plus_key)
    }
}

impl From<PSPublicKey> for OffchainPublicKey {
    fn from(ps_key: PSPublicKey) -> Self {
        Self::PS(ps_key)
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
