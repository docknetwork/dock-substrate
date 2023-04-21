use crate::{
    did::{Did, OnChainDidDetails},
    offchain_signatures::SignatureParams,
    types::CurveType,
    util::{Bytes, IncId},
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{ensure, IterableStorageDoubleMap, StorageDoubleMap};
use sp_runtime::{traits::CheckedConversion, DispatchResult};

use super::{
    AddOffchainSignaturePublicKey, BBSPlusPublicKeyWithParams, Config, Error, Event, Module,
    OffchainSignatureParams, PSPublicKeyWithParams, PublicKeys, RemoveOffchainSignaturePublicKey,
    SignatureParamsStorageKey,
};
use crate::offchain_signatures::OffchainPublicKey;

/// Defines public key and signature params for the given signature schema.
macro_rules! def_signature_schema_key_and_params {
    (for $schema: ident: $(#[$key_meta:meta])* $key: ident, $(#[$params_meta:meta])* $params: ident) => {
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
            pub(crate) participant_id: Option<u16>,
        }

        impl $key {
            /// Instantiates new public key for the BBS+ signature scheme.
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

            /// Instantiates new public key with participant id for the BBS+ signature scheme.
            /// This function doesn't validate supplied bytes.
            /// Participant id implies the usage of this key in threshold issuance.
            pub fn new_participant(
                bytes: impl Into<Bytes>,
                params_ref: impl Into<Option<SignatureParamsStorageKey>>,
                curve_type: CurveType,
                participant_id: u16,
            ) -> Self {
                let mut this = Self::new(bytes, params_ref, curve_type);
                this.participant_id = Some(participant_id);

                this
            }

            /// Combines BBS+ key with signature params (if exist and have BBS+ scheme).
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
                Self::$schema(key)
            }
        }

        impl TryFrom<OffchainPublicKey> for $key {
            type Error = OffchainPublicKey;

            fn try_from(key: OffchainPublicKey) -> Result<$key, OffchainPublicKey> {
                match key {
                    OffchainPublicKey::$schema(key) => Ok(key),
                    other => Err(other),
                }
            }
        }

        impl TryFrom<OffchainPublicKey> for ($key, Option<$params>) {
            type Error = OffchainPublicKey;

            fn try_from(key: OffchainPublicKey) -> Result<($key, Option<$params>), OffchainPublicKey> {
                match key {
                    OffchainPublicKey::$schema(key) => Ok(key.with_params()),
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
            /// Instantiates new parameters for the BBS+ signature scheme.
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
                Self::$schema(ps_params)
            }
        }

        impl TryFrom<OffchainSignatureParams> for $params {
            type Error = OffchainSignatureParams;

            fn try_from(key: OffchainSignatureParams) -> Result<$params, OffchainSignatureParams> {
                match key {
                    OffchainSignatureParams::$schema(params) => Ok(params),
                    other => Err(other),
                }
            }
        }
    }
}

def_signature_schema_key_and_params! {
    for BBS:
        /// Public key for the BBS signature scheme.
        BBSPublicKey,
        /// Signature parameters for the BBS signature scheme.
        BBSParams
}

def_signature_schema_key_and_params! {
    for BBSPlus:
        /// Public key for the BBS+ signature scheme.
        BBSPlusPublicKey,
        /// Signature parameters for the BBS+ signature scheme.
        BBSPlusParams
}

def_signature_schema_key_and_params! {
    for PS:
        /// Public key for the PS signature scheme.
        PSPublicKey,
        /// Signature parameters for the PS signature scheme.
        PSParams
}
