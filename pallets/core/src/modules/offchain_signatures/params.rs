use crate::{
    common::{AuthorizeTarget, Limits, TypesAndLimits},
    did::{DidKey, DidMethodKey, DidOrDidMethodKey},
    offchain_signatures::schemes::*,
    util::{Associated, IncId, OptionExt, StorageRef},
};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{ensure, DebugNoBound};
use sp_runtime::DispatchResult;
use sp_std::fmt::Debug;

use super::{
    AddOffchainSignatureParams, BBSPlusPublicKey, Config, Error, Event, PSPublicKey, Pallet,
    ParamsCounter, RemoveOffchainSignatureParams, SignatureParams,
};

/// DID owner of the signature parameters.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct SignatureParamsOwner(pub DidOrDidMethodKey);

crate::impl_wrapper!(SignatureParamsOwner(DidOrDidMethodKey));

impl<T: TypesAndLimits> AuthorizeTarget<T, Self, DidKey> for SignatureParamsOwner {}
impl<T: TypesAndLimits> AuthorizeTarget<T, Self, DidMethodKey> for SignatureParamsOwner {}
impl<T: TypesAndLimits> AuthorizeTarget<T, (), DidKey> for SignatureParamsOwner {}
impl<T: TypesAndLimits> AuthorizeTarget<T, (), DidMethodKey> for SignatureParamsOwner {}

impl<T: TypesAndLimits> Associated<T> for SignatureParamsOwner {
    type Value = IncId;
}

impl<T: Config> StorageRef<T> for SignatureParamsOwner {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<IncId>) -> Result<R, E>,
    {
        ParamsCounter::<T>::try_mutate_exists(self, |entry| f(entry.initialized()))
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<IncId>) -> R,
    {
        f(Some(ParamsCounter::<T>::get(self)))
    }
}

pub type SignatureParamsStorageKey = (SignatureParamsOwner, IncId);
pub type BBSPublicKeyWithParams<T> = (BBSPublicKey<T>, Option<BBSParameters<T>>);
pub type BBSPlusPublicKeyWithParams<T> = (BBSPlusPublicKey<T>, Option<BBSPlusParameters<T>>);
pub type PSPublicKeyWithParams<T> = (PSPublicKey<T>, Option<PSParameters<T>>);

/// Signature parameters. Currently can be either `BBS`, `BBS+` or `Pointcheval-Sanders`.
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
pub enum OffchainSignatureParams<T: Limits> {
    /// Signature parameters for the BBS signature scheme.
    BBS(BBSParameters<T>),
    /// Signature parameters for the BBS+ signature scheme.
    BBSPlus(BBSPlusParameters<T>),
    /// Signature parameters for the Pointcheval-Sanders signature scheme.
    PS(PSParameters<T>),
}

impl<T: Limits> OffchainSignatureParams<T> {
    /// Returns underlying parameters if it corresponds to the BBS scheme.
    pub fn into_bbs(self) -> Option<BBSParameters<T>> {
        self.try_into().ok()
    }

    /// Returns underlying parameters if it corresponds to the BBS+ scheme.
    pub fn into_bbs_plus(self) -> Option<BBSPlusParameters<T>> {
        self.try_into().ok()
    }

    /// Returns underlying parameters if it corresponds to the Pointcheval-Sanders scheme.
    pub fn into_ps(self) -> Option<PSParameters<T>> {
        self.try_into().ok()
    }

    /// Returns underlying **unchecked** bytes representation for parameters corresponding to either signature scheme.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::BBS(params) => &params.bytes[..],
            Self::BBSPlus(params) => &params.bytes[..],
            Self::PS(params) => &params.bytes[..],
        }
    }

    /// Returns underlying label for a key corresponding to either signature scheme.
    pub fn label(&self) -> Option<&[u8]> {
        match self {
            Self::BBS(params) => params.label.as_ref().map(|slice| &slice[..]),
            Self::BBSPlus(params) => params.label.as_ref().map(|slice| &slice[..]),
            Self::PS(params) => params.label.as_ref().map(|slice| &slice[..]),
        }
    }
}

impl<T: Config> Pallet<T> {
    pub(super) fn add_params_(
        AddOffchainSignatureParams { params, .. }: AddOffchainSignatureParams<T>,
        params_counter: &mut IncId,
        signer: SignatureParamsOwner,
    ) -> DispatchResult {
        SignatureParams::<T>::insert(signer, params_counter.inc(), params);

        Self::deposit_event(Event::ParamsAdded(signer, *params_counter));
        Ok(())
    }

    pub(super) fn remove_params_(
        RemoveOffchainSignatureParams {
            params_ref: (did, counter),
            ..
        }: RemoveOffchainSignatureParams<T>,
        (): (),
        owner: SignatureParamsOwner,
    ) -> DispatchResult {
        // Only the DID that added the param can it
        ensure!(did == owner, Error::<T>::NotOwner);

        ensure!(
            SignatureParams::<T>::contains_key(did, counter),
            Error::<T>::ParamsDontExist
        );

        SignatureParams::<T>::remove(did, counter);

        Self::deposit_event(Event::ParamsRemoved(did, counter));
        Ok(())
    }

    pub fn did_params(
        did: &SignatureParamsOwner,
    ) -> impl Iterator<Item = (IncId, OffchainSignatureParams<T>)> {
        SignatureParams::<T>::iter_prefix(did)
    }
}
