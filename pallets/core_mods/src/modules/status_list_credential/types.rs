use crate::{
    common::{HasPolicy, Policy},
    util::{self, Bytes},
};
use codec::{Decode, Encode};
use core::{
    fmt::Debug,
    ops::{Index, RangeFull},
};
use frame_support::{ensure, traits::Get};
use sp_runtime::DispatchResult;

use super::{Config, StatusListCredentialError};

/// Either [`RevocationList2020Credential`](https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential)
/// or [`StatusList2021Credential`](https://www.w3.org/TR/vc-status-list/#statuslist2021credential).
/// The underlying verifiable credential is represented as a raw byte sequence.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum StatusListCredential {
    /// A verifiable credential that encapsulates a revocation list as per https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential.
    RevocationList2020Credential(Bytes),
    /// A verifiable credential that contains a status list as per https://www.w3.org/TR/vc-status-list/#statuslist2021credential.
    StatusList2021Credential(Bytes),
}

impl StatusListCredential {
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

    /// Ensures that byte length is valid.
    pub fn ensure_valid<T: Config + Debug>(&self) -> Result<(), StatusListCredentialError<T>> {
        ensure!(
            self.len() <= T::MaxStatusListCredentialSize::get(),
            StatusListCredentialError::StatusListCredentialTooBig
        );
        ensure!(
            self.len() >= T::MinStatusListCredentialSize::get(),
            StatusListCredentialError::StatusListCredentialTooSmall
        );

        Ok(())
    }
}

/// `StatusListCredential` combined with `Policy`.
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct StatusListCredentialWithPolicy {
    pub status_list_credential: StatusListCredential,
    pub policy: Policy,
}

impl HasPolicy for StatusListCredentialWithPolicy {
    fn policy(&self) -> &Policy {
        &self.policy
    }
}

impl StatusListCredentialWithPolicy {
    /// Returns underlying raw bytes.
    pub fn bytes(&self) -> &[u8] {
        self.status_list_credential.bytes()
    }

    /// Returns underlying raw bytes length.
    pub fn len(&self) -> u32 {
        self.status_list_credential.len()
    }

    /// Ensures that underlying `Policy` and `StatusListCredential` are valid.
    pub fn ensure_valid<T: Config + Debug>(&self) -> DispatchResult {
        self.policy.ensure_valid::<T>()?;
        self.status_list_credential.ensure_valid::<T>()?;

        Ok(())
    }
}

impl From<StatusListCredentialWithPolicy> for StatusListCredential {
    fn from(
        StatusListCredentialWithPolicy {
            status_list_credential,
            ..
        }: StatusListCredentialWithPolicy,
    ) -> StatusListCredential {
        status_list_credential
    }
}

/// Unique identifier for the `StatusListCredential`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct StatusListCredentialId(
    #[cfg_attr(feature = "serde", serde(with = "util::hex"))] pub [u8; 32],
);

crate::impl_wrapper!(StatusListCredentialId([u8; 32]));

impl Index<RangeFull> for StatusListCredentialId {
    type Output = [u8; 32];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}
