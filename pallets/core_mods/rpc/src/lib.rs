pub use self::gen_client::Client as PriceFeedClient;
use core_mods::accumulator;
use core_mods::bbs_plus;
pub use core_mods::did::Did;
pub use core_mods::runtime_api::CoreModsApi as CoreModsRuntimeApi;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::collections::BTreeMap;
use std::sync::Arc;

#[rpc]
pub trait CoreModsApi<BlockHash> {
    #[rpc(name = "core_mods_bbsPlusPublicKeyWithParams")]
    fn bbs_plus_public_key_with_params(
        &self,
        id: bbs_plus::PublicKeyStorageKey,
        at: Option<BlockHash>,
    ) -> Result<Option<bbs_plus::PublicKeyWithParams>>;

    #[rpc(name = "core_mods_bbsPlusParamsByDid")]
    fn bbs_plus_params_by_did(
        &self,
        did: Did,
        at: Option<BlockHash>,
    ) -> Result<BTreeMap<u32, bbs_plus::BbsPlusParameters>>;

    #[rpc(name = "core_mods_bbsPlusPublicKeysByDid")]
    fn bbs_plus_public_keys_by_did(
        &self,
        did: Did,
        at: Option<BlockHash>,
    ) -> Result<BTreeMap<u32, bbs_plus::PublicKeyWithParams>>;

    #[rpc(name = "core_mods_accumulatorPublicKeyWithParams")]
    fn accumulator_public_key_with_params(
        &self,
        id: accumulator::PublicKeyStorageKey,
        at: Option<BlockHash>,
    ) -> Result<Option<accumulator::PublicKeyWithParams>>;

    #[rpc(name = "core_mods_accumulatorWithPublicKeyAndParams")]
    fn accumulator_with_public_key_and_params(
        &self,
        id: accumulator::AccumulatorId,
        at: Option<BlockHash>,
    ) -> Result<Option<(Vec<u8>, Option<accumulator::PublicKeyWithParams>)>>;
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

impl<C, Block> CoreModsApi<<Block as BlockT>::Hash> for CoreMods<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: CoreModsRuntimeApi<Block>,
{
    fn bbs_plus_public_key_with_params(
        &self,
        id: bbs_plus::PublicKeyStorageKey,
        at: Option<<Block as BlockT>::Hash>,
    ) -> Result<Option<bbs_plus::PublicKeyWithParams>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.bbs_plus_public_key_with_params(&at, id)
            .map_err(|e| RpcError {
                code: ErrorCode::ServerError(2),
                message: "Unable to query BBS+ public key with params".into(),
                data: Some(format!("{:?}", e).into()),
            })
    }

    fn bbs_plus_params_by_did(
        &self,
        did: Did,
        at: Option<<Block as BlockT>::Hash>,
    ) -> Result<BTreeMap<u32, bbs_plus::BbsPlusParameters>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.bbs_plus_params_by_did(&at, did).map_err(|e| RpcError {
            code: ErrorCode::ServerError(1),
            message: "Unable to query BBS+ params of given DID.".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }

    fn bbs_plus_public_keys_by_did(
        &self,
        did: Did,
        at: Option<<Block as BlockT>::Hash>,
    ) -> Result<BTreeMap<u32, bbs_plus::PublicKeyWithParams>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.bbs_plus_public_keys_by_did(&at, did)
            .map_err(|e| RpcError {
                code: ErrorCode::ServerError(1),
                message: "Unable to query BBS+ keys of given DID..".into(),
                data: Some(format!("{:?}", e).into()),
            })
    }

    fn accumulator_public_key_with_params(
        &self,
        id: accumulator::PublicKeyStorageKey,
        at: Option<<Block as BlockT>::Hash>,
    ) -> Result<Option<accumulator::PublicKeyWithParams>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.accumulator_public_key_with_params(&at, id)
            .map_err(|e| RpcError {
                code: ErrorCode::ServerError(1),
                message: "Unable to query accumulator public key with params.".into(),
                data: Some(format!("{:?}", e).into()),
            })
    }

    fn accumulator_with_public_key_and_params(
        &self,
        id: accumulator::AccumulatorId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> Result<Option<(Vec<u8>, Option<accumulator::PublicKeyWithParams>)>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.accumulator_with_public_key_and_params(&at, id)
            .map_err(|e| RpcError {
                code: ErrorCode::ServerError(1),
                message: "Unable to query accumulator with public key and params.".into(),
                data: Some(format!("{:?}", e).into()),
            })
    }
}
