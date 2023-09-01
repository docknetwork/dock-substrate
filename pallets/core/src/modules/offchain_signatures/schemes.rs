use crate::{offchain_signatures::SignatureParams, common::CurveType, util::Bytes};
use codec::{Decode, Encode};
use sp_std::fmt::Debug;
use frame_support::StorageDoubleMap;
use sp_runtime::traits::CheckedConversion;

use super::{OffchainSignatureParams, SignatureParamsStorageKey};
use crate::offchain_signatures::OffchainPublicKey;

/// Identifier of the participant used in the threshold issuance.
pub type ParticipantId = u16;

/// Defines public key and signature params for the given signature scheme.
macro_rules! def_signature_scheme_key_and_params {
    (for $scheme: ident: $(#[$key_meta:meta])* $key: ident, $(#[$params_meta:meta])* $params: ident) => {
        $(#[$key_meta])*
        #[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[scale_info(omit_prefix)]
        pub struct $key {
            /// The public key should be for the same curve as the parameters but a public key might not have
            /// parameters on chain
            pub(crate) curve_type: CurveType,
            pub(crate) bytes: Bytes,
            /// The params used to generate the public key
            pub(crate) params_ref: Option<SignatureParamsStorageKey>,
            /// Optional participant id used in threshold issuance.
            pub(crate) participant_id: Option<ParticipantId>,
        }

        impl $key {
            /// Instantiates new public key for the signature scheme.
            /// This function doesn't validate supplied bytes.
            pub fn new(
                bytes: impl Into<Bytes>,
                params_ref: impl Into<Option<SignatureParamsStorageKey>>,
                curve_type: CurveType,
            ) -> Self {
                Self {
                    bytes: bytes.into(),
                    params_ref: params_ref.into(),
                    curve_type,
                    participant_id: None,
                }
            }

            /// Instantiates new public key with participant id for the signature scheme.
            /// This function doesn't validate supplied bytes.
            /// Participant id implies the usage of this key in threshold issuance.
            pub fn new_with_participant_id(
                bytes: impl Into<Bytes>,
                params_ref: impl Into<Option<SignatureParamsStorageKey>>,
                curve_type: CurveType,
                participant_id: ParticipantId,
            ) -> Self {
                let mut this = Self::new(bytes, params_ref, curve_type);
                this.participant_id = Some(participant_id);

                this
            }

            /// Combines key with signature params (if exist and have same scheme).
            pub fn with_params(self) -> ($key, Option<$params>) {
                let params = self
                    .params_ref
                    .as_ref()
                    .and_then(|(did, params_id)| SignatureParams::get(did, params_id))
                    .and_then(OffchainSignatureParams::checked_into);

                (self, params)
            }
        }

        impl From<$key> for ($key, Option<$params>) {
            fn from(key: $key) -> ($key, Option<$params>) {
                key.with_params()
            }
        }

        impl From<$key> for OffchainPublicKey {
            fn from(key: $key) -> Self {
                Self::$scheme(key)
            }
        }

        impl TryFrom<OffchainPublicKey> for $key {
            type Error = OffchainPublicKey;

            fn try_from(key: OffchainPublicKey) -> Result<$key, OffchainPublicKey> {
                match key {
                    OffchainPublicKey::$scheme(key) => Ok(key),
                    other => Err(other),
                }
            }
        }

        impl TryFrom<OffchainPublicKey> for ($key, Option<$params>) {
            type Error = OffchainPublicKey;

            fn try_from(key: OffchainPublicKey) -> Result<($key, Option<$params>), OffchainPublicKey> {
                match key {
                    OffchainPublicKey::$scheme(key) => Ok(key.with_params()),
                    other => Err(other),
                }
            }
        }

        $(#[$params_meta])*
        #[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[scale_info(omit_prefix)]
        pub struct $params {
            /// The label (generating string) used to generate the params
            pub(crate) label: Option<Bytes>,
            pub(crate) curve_type: CurveType,
            pub(crate) bytes: Bytes,
        }

        impl $params {
            /// Instantiates new parameters for the signature scheme.
            /// This function doesn't validate supplied bytes.
            pub fn new(
                label: impl Into<Option<Bytes>>,
                bytes: impl Into<Bytes>,
                curve_type: CurveType,
            ) -> Self {
                Self {
                    label: label.into(),
                    curve_type,
                    bytes: bytes.into(),
                }
            }
        }

        impl From<$params> for OffchainSignatureParams {
            fn from(ps_params: $params) -> Self {
                Self::$scheme(ps_params)
            }
        }

        impl TryFrom<OffchainSignatureParams> for $params {
            type Error = OffchainSignatureParams;

            fn try_from(key: OffchainSignatureParams) -> Result<$params, OffchainSignatureParams> {
                match key {
                    OffchainSignatureParams::$scheme(params) => Ok(params),
                    other => Err(other),
                }
            }
        }
    }
}

def_signature_scheme_key_and_params! {
    for BBS:
        /// Public key for the BBS signature scheme.
        BBSPublicKey,
        /// Signature parameters for the BBS signature scheme.
        BBSParameters
}

def_signature_scheme_key_and_params! {
    for BBSPlus:
        /// Public key for the BBS+ signature scheme.
        BBSPlusPublicKey,
        /// Signature parameters for the BBS+ signature scheme.
        BBSPlusParameters
}

def_signature_scheme_key_and_params! {
    for PS:
        /// Public key for the PS signature scheme.
        PSPublicKey,
        /// Signature parameters for the PS signature scheme.
        PSParameters
}
