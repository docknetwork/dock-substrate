use crate::{
    did::Did,
    types::CurveType,
    util::{IncId, WrappedBytes},
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{ensure, traits::Get, IterableStorageDoubleMap, StorageDoubleMap, StorageMap};
use sp_runtime::DispatchResult;

use super::{
    AddOffchainSignatureParams, BBSPlusPublicKey, Config, Error, Event, Module, PSPublicKey,
    ParamsCounter, RemoveOffchainSignatureParams, SignatureParams,
};

/// DID owner of the signature parameters.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct SignatureParamsOwner(pub Did);

crate::impl_wrapper!(SignatureParamsOwner(Did), for rand use Did(rand::random()), with tests as bbs_plus_params_owner_tests);

pub type OffchainSignatureParamsStorageKey = (SignatureParamsOwner, IncId);
pub type BBSPlusPublicKeyWithParams = (BBSPlusPublicKey, Option<BBSPlusParams>);
pub type PSPublicKeyWithParams = (PSPublicKey, Option<PSParams>);

/// Signature parameters. Currently can be either BBS+ or Pointcheval-Sanders.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum OffchainSignatureParams {
    /// Signature parameters for the BBS+ signature scheme.
    BBSPlus(BBSPlusParams),
    /// Signature parameters for the Pointcheval-Sanders signature scheme.
    PS(PSParams),
}

impl OffchainSignatureParams {
    /// Returns underlying parameters if it corresponds to the BBS+ scheme.
    pub fn into_bbs_plus(self) -> Option<BBSPlusParams> {
        self.try_into().ok()
    }

    /// Returns underlying parameters if it corresponds to the Pointcheval-Sanders scheme.
    pub fn into_ps(self) -> Option<PSParams> {
        self.try_into().ok()
    }

    /// Returns underlying **unchecked** bytes representation for a key corresponding to either signature scheme.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::BBSPlus(params) => &params.bytes[..],
            Self::PS(params) => &params.bytes[..],
        }
    }

    /// Returns underlying label for a key corresponding to either signature scheme.
    pub fn label(&self) -> Option<&[u8]> {
        match self {
            Self::BBSPlus(params) => params.label.as_ref().map(|slice| &slice[..]),
            Self::PS(params) => params.label.as_ref().map(|slice| &slice[..]),
        }
    }

    /// Ensures that signature parameters have valid size.
    pub fn ensure_valid<T: Config + Debug>(&self) -> Result<(), Error<T>> {
        ensure!(
            T::LabelMaxSize::get() as usize >= self.label().map_or(0, <[_]>::len),
            Error::<T>::LabelTooBig
        );
        ensure!(
            T::ParamsMaxSize::get() as usize >= self.bytes().len(),
            Error::<T>::ParamsTooBig
        );

        Ok(())
    }
}

/// Signature parameters for the BBS+ signature scheme.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct BBSPlusParams(SingatureParamsBase);
crate::impl_wrapper! { no_wrapper_from_type BBSPlusParams(SingatureParamsBase) }

/// Signature parameters for the Pointcheval-Sanders signature scheme.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct PSParams(SingatureParamsBase);
crate::impl_wrapper! { no_wrapper_from_type PSParams(SingatureParamsBase) }

impl BBSPlusParams {
    /// Instantiates new parameters for the BBS+ signature scheme.
    /// This function doesn't validate supplied bytes.
    pub fn new(
        label: impl Into<Option<WrappedBytes>>,
        bytes: impl Into<WrappedBytes>,
        curve_type: CurveType,
    ) -> Self {
        Self(SingatureParamsBase {
            label: label.into(),
            curve_type,
            bytes: bytes.into(),
        })
    }
}

impl PSParams {
    /// Instantiates new parameters for the BBS+ signature scheme.
    /// This function doesn't validate supplied bytes.
    pub fn new(
        label: impl Into<Option<WrappedBytes>>,
        bytes: impl Into<WrappedBytes>,
        curve_type: CurveType,
    ) -> Self {
        Self(SingatureParamsBase {
            label: label.into(),
            curve_type,
            bytes: bytes.into(),
        })
    }
}

/// Defines shared base for the signature params. Can be changed later.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct SingatureParamsBase {
    /// The label (generating string) used to generate the params
    pub label: Option<WrappedBytes>,
    pub curve_type: CurveType,
    pub bytes: WrappedBytes,
}

impl From<BBSPlusParams> for OffchainSignatureParams {
    fn from(bbs_plus_params: BBSPlusParams) -> Self {
        Self::BBSPlus(bbs_plus_params)
    }
}

impl From<PSParams> for OffchainSignatureParams {
    fn from(ps_params: PSParams) -> Self {
        Self::PS(ps_params)
    }
}

impl TryFrom<OffchainSignatureParams> for BBSPlusParams {
    type Error = OffchainSignatureParams;

    fn try_from(key: OffchainSignatureParams) -> Result<Self, OffchainSignatureParams> {
        match key {
            OffchainSignatureParams::BBSPlus(params) => Ok(params),
            other => Err(other),
        }
    }
}

impl TryFrom<OffchainSignatureParams> for PSParams {
    type Error = OffchainSignatureParams;

    fn try_from(key: OffchainSignatureParams) -> Result<Self, OffchainSignatureParams> {
        match key {
            OffchainSignatureParams::PS(key) => Ok(key),
            other => Err(other),
        }
    }
}

impl<T: Config + Debug> Module<T> {
    pub(super) fn add_params_(
        AddOffchainSignatureParams { params, .. }: AddOffchainSignatureParams<T>,
        signer: SignatureParamsOwner,
    ) -> DispatchResult {
        params.ensure_valid::<T>()?;

        let params_count = ParamsCounter::mutate(signer, |counter| *counter.inc());
        SignatureParams::insert(signer, params_count, params);

        Self::deposit_event(Event::ParamsAdded(signer, params_count));
        Ok(())
    }

    pub(super) fn remove_params_(
        RemoveOffchainSignatureParams {
            params_ref: (did, counter),
            ..
        }: RemoveOffchainSignatureParams<T>,
        owner: SignatureParamsOwner,
    ) -> DispatchResult {
        // Only the DID that added the param can it
        ensure!(did == owner, Error::<T>::NotOwner);

        ensure!(
            SignatureParams::contains_key(&did, &counter),
            Error::<T>::ParamsDontExist
        );

        SignatureParams::remove(&did, &counter);

        Self::deposit_event(Event::ParamsRemoved(did, counter));
        Ok(())
    }

    pub fn did_params(
        did: &SignatureParamsOwner,
    ) -> impl Iterator<Item = (IncId, OffchainSignatureParams)> {
        SignatureParams::iter_prefix(did)
    }
}
