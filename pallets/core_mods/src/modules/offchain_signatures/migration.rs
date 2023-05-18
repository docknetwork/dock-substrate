use crate::{
    did::*,
    offchain_signatures::{
        self, Config, OffchainPublicKey, OffchainSignatureParams, PublicKeys, SignatureParams,
        SignatureParamsOwner, SignatureParamsStorageKey,
    },
    types::CurveType,
    util::*,
};
use alloc::vec;
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    traits::{Get, GetStorageVersion, PalletInfoAccess},
    weights::Weight,
    *,
};

/// DID owner of the BBSPlus parameters.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
pub struct BBSPlusParamsOwner(pub Did);
crate::impl_wrapper!(BBSPlusParamsOwner(Did), for rand use Did(rand::random()), with tests as bbs_plus_params_owner_tests);

/// Public key for BBS+ keys
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BBSPlusPublicKey {
    /// The public key should be for the same curve as the parameters but a public key might not have
    /// parameters on chain
    pub curve_type: CurveType,
    pub bytes: Bytes,
    /// The params used to generate the public key (`g2` comes from params)
    pub params_ref: Option<SignatureParamsStorageKey>,
}
/// BBSPlus params
#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BBSPlusParameters {
    /// The label (generating string) used to generate the params
    pub label: Option<Bytes>,
    pub curve_type: CurveType,
    pub bytes: Bytes,
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {}
}

decl_storage! {
    trait Store for Module<T: Config> as BBSPlusModule where T: Debug {
        /// Pair of counters where each is used to assign unique id to parameters and public keys
        /// respectively. On adding new params or keys, corresponding counter is increased by 1 but
        /// the counters don't decrease on removal
        pub ParamsCounter get(fn params_counter):
            map hasher(blake2_128_concat) BBSPlusParamsOwner => IncId;

        /// Parameters are stored as key value (did, counter) -> params
        pub BbsPlusParams get(fn get_params):
            double_map hasher(blake2_128_concat) BBSPlusParamsOwner, hasher(identity) IncId => Option<BBSPlusParameters>;

        /// Public keys are stored as key value (did, counter) -> public key
        /// Its assumed that the public keys are always members of G2. It does impact any logic on the
        /// chain but makes up for one less storage value
        pub BbsPlusKeys get(fn get_key):
            double_map hasher(blake2_128_concat) Did, hasher(identity) IncId => Option<BBSPlusPublicKey>;
    }
}

pub fn migrate<T: Config, P: GetStorageVersion + PalletInfoAccess>() -> Weight {
    let new_pallet_name = <P as PalletInfoAccess>::name();

    frame_support::storage::migration::move_storage_from_pallet(
        b"ParamsCounter",
        b"BBSPlusModule",
        new_pallet_name.as_bytes(),
    );
    frame_support::storage::migration::move_storage_from_pallet(
        b"Version",
        b"BBSPlusModule",
        new_pallet_name.as_bytes(),
    );

    for (did, id, params) in BbsPlusParams::drain() {
        frame_support::log::info!("BBS+ params with id={:?} migrated for did={:?}", id, did);
        let bbs_plus_key: OffchainSignatureParams = offchain_signatures::BBSPlusParameters::new(
            params.label,
            params.bytes,
            params.curve_type,
        )
        .into();

        SignatureParams::insert(SignatureParamsOwner::from(*did), id, bbs_plus_key);
    }

    for (did, id, key) in BbsPlusKeys::drain() {
        frame_support::log::info!("BBS+ key with id={:?} migrated for did={:?}", id, did);
        let bbs_plus_key: OffchainPublicKey =
            offchain_signatures::BBSPlusPublicKey::new(key.bytes, key.params_ref, key.curve_type)
                .into();

        PublicKeys::insert(did, id, bbs_plus_key);
    }

    <T as frame_system::Config>::BlockWeights::get().max_block
}
