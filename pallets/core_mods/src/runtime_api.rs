use crate::{
    accumulator,
    did::{self, Config},
    offchain_signatures,
    util::IncId,
};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

sp_api::decl_runtime_apis! {
    pub trait CoreModsApi<T: Config> {
        fn did_details(id: did::Did, params: Option<did::AggregatedDidDetailsRequestParams>) -> Option<did::AggregatedDidDetailsResponse<T>>;

        fn did_list_details(dids: Vec<did::Did>, params: Option<did::AggregatedDidDetailsRequestParams>) -> Vec<Option<did::AggregatedDidDetailsResponse<T>>>;

        fn bbs_public_key_with_params(id: offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::BBSPublicKeyWithParams>;

        fn bbs_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::BBSParams>;

        fn bbs_public_keys_by_did(did: crate::did::Did) -> BTreeMap<IncId, offchain_signatures::BBSPublicKeyWithParams>;

        fn bbs_plus_public_key_with_params(id: offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::BBSPlusPublicKeyWithParams>;

        fn bbs_plus_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::BBSPlusParams>;

        fn bbs_plus_public_keys_by_did(did: crate::did::Did) -> BTreeMap<IncId, offchain_signatures::BBSPlusPublicKeyWithParams>;

        fn ps_public_key_with_params(id: offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::PSPublicKeyWithParams>;

        fn ps_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::PSParams>;

        fn ps_public_keys_by_did(did: crate::did::Did) -> BTreeMap<IncId, offchain_signatures::PSPublicKeyWithParams>;

        fn accumulator_public_key_with_params(id: accumulator::AccumPublicKeyStorageKey) -> Option<accumulator::AccumPublicKeyWithParams>;

        fn accumulator_with_public_key_and_params(id: accumulator::AccumulatorId) -> Option<(Vec<u8>, Option<accumulator::AccumPublicKeyWithParams>)>;
    }
}
