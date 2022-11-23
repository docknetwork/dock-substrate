use core::{fmt::Debug, marker::PhantomData};
use core_mods::{accumulator, bbs_plus, util::IncId};
pub use core_mods::{
    did::{self, Config},
    runtime_api::CoreModsApi as CoreModsRuntimeApi,
};
use jsonrpsee::{
    core::{async_trait, Error as JsonRpseeError, RpcResult},
    proc_macros::rpc,
    types::{error::CallError, ErrorObject},
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::{collections::BTreeMap, sync::Arc};

pub trait ConfigWrapper {
    type T: Config;
}

/// To be used in places where `Serialize`/`Deserialize` bounds required for `Config`.
#[derive(Default, Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))]
pub struct SerializableConfigWrapper<T>(PhantomData<T>);

impl<T: Config> ConfigWrapper for SerializableConfigWrapper<T> {
    type T = T;
}

#[rpc(server, client)]
pub trait CoreModsApi<BlockHash, Config>
where
    Config: ConfigWrapper,
{
    #[method(name = "core_mods_didDetails")]
    async fn did_details(
        &self,
        did: did::Did,
        params: Option<did::AggregatedDidDetailsRequestParams>,
        at: Option<BlockHash>,
    ) -> RpcResult<Option<did::AggregatedDidDetailsResponse<Config::T>>>;

    #[method(name = "core_mods_didListDetails")]
    async fn did_list_details(
        &self,
        dids: Vec<did::Did>,
        params: Option<did::AggregatedDidDetailsRequestParams>,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<Option<did::AggregatedDidDetailsResponse<Config::T>>>>;

    #[method(name = "core_mods_bbsPlusPublicKeyWithParams")]
    async fn bbs_plus_public_key_with_params(
        &self,
        id: bbs_plus::BBSPlusPublicKeyStorageKey,
        at: Option<BlockHash>,
    ) -> RpcResult<Option<bbs_plus::BBSPlusPublicKeyWithParams>>;

    #[method(name = "core_mods_bbsPlusParamsByDid")]
    async fn bbs_plus_params_by_did(
        &self,
        owner: bbs_plus::BBSPlusParamsOwner,
        at: Option<BlockHash>,
    ) -> RpcResult<BTreeMap<IncId, bbs_plus::BBSPlusParameters>>;

    #[method(name = "core_mods_bbsPlusPublicKeysByDid")]
    async fn bbs_plus_public_keys_by_did(
        &self,
        did: did::Did,
        at: Option<BlockHash>,
    ) -> RpcResult<BTreeMap<IncId, bbs_plus::BBSPlusPublicKeyWithParams>>;

    #[method(name = "core_mods_accumulatorPublicKeyWithParams")]
    async fn accumulator_public_key_with_params(
        &self,
        id: accumulator::AccumPublicKeyStorageKey,
        at: Option<BlockHash>,
    ) -> RpcResult<Option<accumulator::AccumPublicKeyWithParams>>;

    #[method(name = "core_mods_accumulatorWithPublicKeyAndParams")]
    async fn accumulator_with_public_key_and_params(
        &self,
        id: accumulator::AccumulatorId,
        at: Option<BlockHash>,
    ) -> RpcResult<Option<(Vec<u8>, Option<accumulator::AccumPublicKeyWithParams>)>>;
}

/// A struct that implements the [`CoreModsApi`].
pub struct CoreMods<C, P> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<P>,
}

impl<C, P> CoreMods<C, P> {
    /// Create new `PriceFeed` with the given reference to the client.
    pub fn new(client: Arc<C>) -> Self {
        CoreMods {
            client,
            _marker: Default::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct Error<T>(T);

impl<T: Debug> From<Error<T>> for JsonRpseeError {
    fn from(error: Error<T>) -> Self {
        let data = format!("{:?}", error);

        JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
            1,
            "Runtime error",
            Some(data),
        )))
    }
}

#[async_trait]
impl<C, Block, T> CoreModsApiServer<<Block as BlockT>::Hash, T> for CoreMods<C, Block>
where
    Block: BlockT,
    T: ConfigWrapper,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: CoreModsRuntimeApi<Block, T::T>,
{
    async fn did_details(
        &self,
        did: did::Did,
        params: Option<did::AggregatedDidDetailsRequestParams>,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<did::AggregatedDidDetailsResponse<T::T>>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));

        api.did_details(&at, did, params)
            .map_err(Error)
            .map_err(Into::into)
    }

    async fn did_list_details(
        &self,
        dids: Vec<did::Did>,
        params: Option<did::AggregatedDidDetailsRequestParams>,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<Option<did::AggregatedDidDetailsResponse<T::T>>>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));

        api.did_list_details(&at, dids, params)
            .map_err(Error)
            .map_err(Into::into)
    }
    async fn bbs_plus_public_key_with_params(
        &self,
        id: bbs_plus::BBSPlusPublicKeyStorageKey,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<bbs_plus::BBSPlusPublicKeyWithParams>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.bbs_plus_public_key_with_params(&at, id)
            .map_err(Error)
            .map_err(Into::into)
    }

    async fn bbs_plus_params_by_did(
        &self,
        owner: bbs_plus::BBSPlusParamsOwner,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<BTreeMap<IncId, bbs_plus::BBSPlusParameters>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.bbs_plus_params_by_did(&at, owner)
            .map_err(Error)
            .map_err(Into::into)
    }

    async fn bbs_plus_public_keys_by_did(
        &self,
        did: did::Did,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<BTreeMap<IncId, bbs_plus::BBSPlusPublicKeyWithParams>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.bbs_plus_public_keys_by_did(&at, did)
            .map_err(Error)
            .map_err(Into::into)
    }

    async fn accumulator_public_key_with_params(
        &self,
        id: accumulator::AccumPublicKeyStorageKey,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<accumulator::AccumPublicKeyWithParams>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.accumulator_public_key_with_params(&at, id)
            .map_err(Error)
            .map_err(Into::into)
    }

    async fn accumulator_with_public_key_and_params(
        &self,
        id: accumulator::AccumulatorId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<(Vec<u8>, Option<accumulator::AccumPublicKeyWithParams>)>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.accumulator_with_public_key_and_params(&at, id)
            .map_err(Error)
            .map_err(Into::into)
    }
}
