use crate::{
    common::{CurveType, Limits},
    offchain_signatures::SignatureParams,
    util::BoundedBytes,
};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};
use sp_runtime::traits::CheckedConversion;

use super::{Config, OffchainSignatureParams, SignatureParamsStorageKey};
use crate::offchain_signatures::OffchainPublicKey;

/// Identifier of the participant used in the threshold issuance.
pub type ParticipantId = u16;

/// Defines public key and signature params for the given signature scheme.
macro_rules! def_signature_scheme_key_and_params {
    (for $scheme: ident: $(#[$key_meta:meta])* $key: ident<$key_byte_size: ident>, $(#[$params_meta:meta])* $params: ident<$params_byte_size: ident>) => {
        $(#[$key_meta])*
        #[derive(scale_info_derive::TypeInfo, Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
        #[cfg_attr(
            feature = "serde",
            serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
        )]
        #[scale_info(skip_type_params(T))]
        #[scale_info(omit_prefix)]
        pub struct $key<T: Limits> {
            /// The public key should be for the same curve as the parameters but a public key might not have
            /// parameters on chain
            pub(crate) curve_type: CurveType,
            pub(crate) bytes: BoundedBytes<T::$key_byte_size>,
            /// The params used to generate the public key
            pub(crate) params_ref: Option<SignatureParamsStorageKey>,
            /// Optional participant id used in threshold issuance.
            pub(crate) participant_id: Option<ParticipantId>,
        }

        impl<T: Limits> $key<T> {
            /// Instantiates new public key for the signature scheme.
            /// This function doesn't validate supplied bytes.
            pub fn new(
                bytes: BoundedBytes<T::$key_byte_size>,
                params_ref: impl Into<Option<SignatureParamsStorageKey>>,
                curve_type: CurveType,
            ) -> Self {
                Self {
                    bytes,
                    params_ref: params_ref.into(),
                    curve_type,
                    participant_id: None,
                }
            }

            /// Instantiates new public key with participant id for the signature scheme.
            /// This function doesn't validate supplied bytes.
            /// Participant id implies the usage of this key in threshold issuance.
            pub fn new_with_participant_id(
                bytes: BoundedBytes<T::$key_byte_size>,
                params_ref: impl Into<Option<SignatureParamsStorageKey>>,
                curve_type: CurveType,
                participant_id: ParticipantId,
            ) -> Self {
                let mut this = Self::new(bytes, params_ref, curve_type);
                this.participant_id = Some(participant_id);

                this
            }

            /// Combines key with signature params (if exist and have same scheme).
            pub fn with_params(self) -> ($key<T>, Option<$params<T>>) where T: Config {
                let params = self
                    .params_ref
                    .as_ref()
                    .and_then(|(did, params_id)| SignatureParams::<T>::get(did, params_id))
                    .and_then(OffchainSignatureParams::checked_into);

                (self, params)
            }
        }

        impl<T: Config> From<$key<T>> for ($key<T>, Option<$params<T>>) {
            fn from(key: $key<T>) -> ($key<T>, Option<$params<T>>) {
                key.with_params()
            }
        }

        impl<T: Limits> From<$key<T>> for OffchainPublicKey<T> {
            fn from(key: $key<T>) -> Self {
                Self::$scheme(key)
            }
        }

        impl<T: Limits> TryFrom<OffchainPublicKey<T>> for $key<T> {
            type Error = OffchainPublicKey<T>;

            fn try_from(key: OffchainPublicKey<T>) -> Result<$key<T>, OffchainPublicKey<T>> {
                match key {
                    OffchainPublicKey::$scheme(key) => Ok(key),
                    other => Err(other),
                }
            }
        }

        impl<T: Config> TryFrom<OffchainPublicKey<T>> for ($key<T>, Option<$params<T>>) {
            type Error = OffchainPublicKey<T>;

            fn try_from(key: OffchainPublicKey<T>) -> Result<($key<T>, Option<$params<T>>), OffchainPublicKey<T>> {
                match key {
                    OffchainPublicKey::$scheme(key) => Ok(key.with_params()),
                    other => Err(other),
                }
            }
        }

        $(#[$params_meta])*
        #[derive(scale_info_derive::TypeInfo, Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
        #[cfg_attr(
            feature = "serde",
            serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
        )]
        #[scale_info(skip_type_params(T))]
        #[scale_info(omit_prefix)]
        pub struct $params<T: Limits> {
            /// The label (generating string) used to generate the params
            pub(crate) label: Option<BoundedBytes<T::MaxOffchainParamsLabelSize>>,
            pub(crate) curve_type: CurveType,
            pub(crate) bytes: BoundedBytes<T::$params_byte_size>,
        }

        impl<T: Limits> $params<T> {
            /// Instantiates new parameters for the signature scheme.
            /// This function doesn't validate supplied bytes.
            pub fn new(
                label: impl Into<Option<BoundedBytes<T::MaxOffchainParamsLabelSize>>>,
                bytes: BoundedBytes<T::$params_byte_size>,
                curve_type: CurveType,
            ) -> Self {
                Self {
                    label: label.into(),
                    curve_type,
                    bytes,
                }
            }
        }

        impl<T: Limits> From<$params<T>> for OffchainSignatureParams<T> {
            fn from(params: $params<T>) -> Self {
                Self::$scheme(params)
            }
        }

        impl<T: Limits> TryFrom<OffchainSignatureParams<T>> for $params<T> {
            type Error = OffchainSignatureParams<T>;

            fn try_from(key: OffchainSignatureParams<T>) -> Result<$params<T>, OffchainSignatureParams<T>> {
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
        BBSPublicKey<MaxBBSPublicKeySize>,
        /// Signature parameters for the BBS signature scheme.
        BBSParameters<MaxOffchainParamsBytesSize>
}

def_signature_scheme_key_and_params! {
    for BBSPlus:
        /// Public key for the BBS+ signature scheme.
        BBSPlusPublicKey<MaxBBSPlusPublicKeySize>,
        /// Signature parameters for the BBS+ signature scheme.
        BBSPlusParameters<MaxOffchainParamsBytesSize>
}

def_signature_scheme_key_and_params! {
    for PS:
        /// Public key for the PS signature scheme.
        PSPublicKey<MaxPSPublicKeySize>,
        /// Signature parameters for the PS signature scheme.
        PSParameters<MaxOffchainParamsBytesSize>
}
