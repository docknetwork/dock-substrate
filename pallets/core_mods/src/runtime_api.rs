use crate::{
    accumulator, bbs_plus,
    did::{self, Config},
    util::IncId,
};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

sp_api::decl_runtime_apis! {
    pub trait CoreModsApi<T: Config> {
        fn did_details(id: did::Did, params: Option<did::AggregatedDidDetailsRequestParams>) -> Option<did::AggregatedDidDetailsResponse<T>>;

        fn did_list_details(dids: Vec<did::Did>, params: Option<did::AggregatedDidDetailsRequestParams>) -> Vec<Option<did::AggregatedDidDetailsResponse<T>>>;

        fn bbs_plus_public_key_with_params(id: bbs_plus::BBSPlusPublicKeyStorageKey) -> Option<bbs_plus::BBSPlusPublicKeyWithParams>;

        fn bbs_plus_params_by_did(owner: bbs_plus::BBSPlusParamsOwner) -> BTreeMap<IncId, bbs_plus::BBSPlusParameters>;

        fn bbs_plus_public_keys_by_did(did: crate::did::Did) -> BTreeMap<IncId, bbs_plus::BBSPlusPublicKeyWithParams>;

        fn accumulator_public_key_with_params(id: accumulator::AccumPublicKeyStorageKey) -> Option<accumulator::AccumPublicKeyWithParams>;

        fn accumulator_with_public_key_and_params(id: accumulator::AccumulatorId) -> Option<(Vec<u8>, Option<accumulator::AccumPublicKeyWithParams>)>;
    }
}
