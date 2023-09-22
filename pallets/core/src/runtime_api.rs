use crate::{accumulator, common::TypesAndLimits, did, offchain_signatures, util::IncId};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

sp_api::decl_runtime_apis! {
    pub trait CoreModsApi<T: TypesAndLimits> {
        fn did_details(id: did::Did, params: Option<did::AggregatedDidDetailsRequestParams>) -> Option<did::AggregatedDidDetailsResponse<T>>;

        fn did_list_details(dids: Vec<did::Did>, params: Option<did::AggregatedDidDetailsRequestParams>) -> Vec<Option<did::AggregatedDidDetailsResponse<T>>>;

        fn bbs_public_key_with_params(id: offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::BBSPublicKeyWithParams<T>>;

        fn bbs_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::BBSParameters<T>>;

        fn bbs_public_keys_by_did(did: crate::did::Did) -> BTreeMap<IncId, offchain_signatures::BBSPublicKeyWithParams<T>>;

        fn bbs_plus_public_key_with_params(id: offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::BBSPlusPublicKeyWithParams<T>>;

        fn bbs_plus_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::BBSPlusParameters<T>>;

        fn bbs_plus_public_keys_by_did(did: crate::did::Did) -> BTreeMap<IncId, offchain_signatures::BBSPlusPublicKeyWithParams<T>>;

        fn ps_public_key_with_params(id: offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::PSPublicKeyWithParams<T>>;

        fn ps_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::PSParameters<T>>;

        fn ps_public_keys_by_did(did: crate::did::Did) -> BTreeMap<IncId, offchain_signatures::PSPublicKeyWithParams<T>>;

        fn accumulator_public_key_with_params(id: accumulator::AccumPublicKeyStorageKey) -> Option<accumulator::AccumPublicKeyWithParams<T>>;

        fn accumulator_with_public_key_and_params(id: accumulator::AccumulatorId) -> Option<(Vec<u8>, Option<accumulator::AccumPublicKeyWithParams<T>>)>;
    }
}
