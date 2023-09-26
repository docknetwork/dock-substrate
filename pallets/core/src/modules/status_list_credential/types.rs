#[cfg(feature = "serde")]
use crate::util::hex;
use crate::{
    common::{HasPolicy, Limits, Policy},
    util::BoundedBytes,
};
use codec::{Decode, Encode, MaxEncodedLen};
use core::fmt::Debug;
use frame_support::{traits::Get, DebugNoBound, *};
use sp_runtime::DispatchResult;

use super::{Config, Error};

/// Either [`RevocationList2020Credential`](https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential)
/// or [`StatusList2021Credential`](https://www.w3.org/TR/vc-status-list/#statuslist2021credential).
/// The underlying verifiable credential is represented as a raw byte sequence.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub enum StatusListCredential<T: Limits> {
    /// A verifiable credential that encapsulates a revocation list as per https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential.
    RevocationList2020Credential(BoundedBytes<T::MaxStatusListCredentialSize>),
    /// A verifiable credential that contains a status list as per https://www.w3.org/TR/vc-status-list/#statuslist2021credential.
    StatusList2021Credential(BoundedBytes<T::MaxStatusListCredentialSize>),
}

impl<T: Limits> StatusListCredential<T> {
    /// Returns underlying raw bytes.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::RevocationList2020Credential(bytes) => bytes,
            Self::StatusList2021Credential(bytes) => bytes,
        }
    }

    /// Returns underlying raw bytes length.
    pub fn len(&self) -> u32 {
        self.bytes().len() as u32
    }

    /// Returns `true` if underlying raw bytes length is equal to zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ensures that byte length is valid.
    pub fn ensure_valid(&self) -> Result<(), Error<T>>
    where
        T: Config,
    {
        ensure!(
            self.len() >= T::MinStatusListCredentialSize::get(),
            Error::StatusListCredentialTooSmall
        );

        Ok(())
    }
}

/// `StatusListCredential` combined with `Policy`.
#[derive(
    scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, DebugNoBound, MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct StatusListCredentialWithPolicy<T: Limits> {
    pub status_list_credential: StatusListCredential<T>,
    pub policy: Policy<T>,
}

impl<T: Limits> HasPolicy<T> for StatusListCredentialWithPolicy<T> {
    fn policy(&self) -> &Policy<T> {
        &self.policy
    }
}

impl<T: Limits> StatusListCredentialWithPolicy<T> {
    /// Returns underlying raw bytes.
    pub fn bytes(&self) -> &[u8] {
        self.status_list_credential.bytes()
    }

    /// Returns underlying raw bytes length.
    pub fn len(&self) -> u32 {
        self.status_list_credential.len()
    }

    /// Returns `true` if underlying raw bytes length is equal to zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ensures that underlying `Policy` and `StatusListCredential` are valid.
    pub fn ensure_valid(&self) -> DispatchResult
    where
        T: Config,
    {
        self.policy.ensure_valid()?;
        self.status_list_credential.ensure_valid()?;

        Ok(())
    }
}

impl<T: Limits> From<StatusListCredentialWithPolicy<T>> for StatusListCredential<T> {
    fn from(
        StatusListCredentialWithPolicy {
            status_list_credential,
            ..
        }: StatusListCredentialWithPolicy<T>,
    ) -> StatusListCredential<T> {
        status_list_credential
    }
}

/// Unique identifier for the `StatusListCredential`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct StatusListCredentialId(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

crate::impl_wrapper!(StatusListCredentialId([u8; 32]));
