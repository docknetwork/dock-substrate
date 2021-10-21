use crate::bbs_plus::{
    BBSPlusParameters, ParametersStorageKey, PublicKeyStorageKey, PublicKeyWithParams,
};
use sp_std::collections::btree_map::BTreeMap;

sp_api::decl_runtime_apis! {
    pub trait CoreModsApi {
        fn bbs_plus_params(id: ParametersStorageKey) -> Option<BBSPlusParameters>;

        fn bbs_plus_public_key_with_params(id: PublicKeyStorageKey) -> Option<PublicKeyWithParams>;

        fn bbs_plus_params_by_did(did: crate::did::Did) -> BTreeMap<u32, BBSPlusParameters>;

        fn bbs_plus_public_keys_by_did(did: crate::did::Did) -> BTreeMap<u32, PublicKeyWithParams>;
    }
}
