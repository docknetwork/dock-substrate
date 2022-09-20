use core::fmt::Debug;
use jsonrpsee::{
    core::{async_trait, Error as JsonRpseeError, RpcResult},
    proc_macros::rpc,
    types::{error::CallError, ErrorObject},
};
pub use price_feed::runtime_api::PriceFeedApi as PriceFeedRuntimeApi;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::sync::Arc;

#[rpc(server, client)]
pub trait PriceFeedApi<BlockHash> {
    /// Gets the price of Dock/USD from pallet's storage
    #[method(name = "price_feed_tokenUsdPrice")]
    async fn token_usd_price(&self, at: Option<BlockHash>) -> RpcResult<Option<u32>>;

    /// Gets the price of Dock/USD from EVM contract
    #[method(name = "price_feed_tokenUsdPriceFromContract")]
    async fn token_usd_price_from_contract(&self, at: Option<BlockHash>) -> RpcResult<Option<u32>>;
}

/// A struct that implements the [`PriceFeedApi`].
pub struct PriceFeed<C, P> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<P>,
}

impl<C, P> PriceFeed<C, P> {
    /// Create new `PriceFeed` with the given reference to the client.
    pub fn new(client: Arc<C>) -> Self {
        PriceFeed {
            client,
            _marker: Default::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeError<T>(T);

impl<T: Debug> From<RuntimeError<T>> for JsonRpseeError {
    fn from(error: RuntimeError<T>) -> Self {
        let data = format!("{:?}", error);

        JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
            1,
            "Runtime error",
            Some(data),
        )))
    }
}

#[async_trait]
impl<C, Block> PriceFeedApiServer<<Block as BlockT>::Hash> for PriceFeed<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: PriceFeedRuntimeApi<Block>,
{
    async fn token_usd_price(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<Option<u32>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.token_usd_price(&at)
            .map_err(RuntimeError)
            .map_err(Into::into)
    }

    async fn token_usd_price_from_contract(
        &self,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<u32>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.token_usd_price_from_contract(&at)
            .map_err(RuntimeError)
            .map_err(Into::into)
    }
}
