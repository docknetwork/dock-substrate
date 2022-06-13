//use crate::accumulator;
// use crate::bbs_plus;
use crate::did::{self, Trait};
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    pub trait CoreModsApi<T: Trait> {
        fn did_details(id: did::Did, params: Option<did::DidRequestParams>) -> Option<did::DidDetailsResponse<T>>;

        fn did_list_details(dids: Vec<did::Did>, params: Option<did::DidRequestParams>) -> Vec<Option<did::DidDetailsResponse<T>>>;

        /*fn bbs_plus_public_key_with_params(id: bbs_plus::PublicKeyStorageKey) -> Option<bbs_plus::PublicKeyWithParams>;

        fn bbs_plus_params_by_did(did: crate::did::Did) -> BTreeMap<u32, bbs_plus::BbsPlusParameters>;

        fn bbs_plus_public_keys_by_did(did: crate::did::Did) -> BTreeMap<u32, bbs_plus::PublicKeyWithParams>;

        fn accumulator_public_key_with_params(id: accumulator::PublicKeyStorageKey) -> Option<accumulator::PublicKeyWithParams>;

        fn accumulator_with_public_key_and_params(id: accumulator::AccumulatorId) -> Option<(Vec<u8>, Option<accumulator::PublicKeyWithParams>)>;*/
    }
}
