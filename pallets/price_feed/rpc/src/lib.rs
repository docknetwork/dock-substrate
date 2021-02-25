pub use self::gen_client::Client as PriceFeedClient;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
pub use price_feed::runtime_api::PriceFeedApi as PriceFeedRuntimeApi;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::sync::Arc;

#[rpc]
pub trait PriceFeedApi<BlockHash> {
    #[rpc(name = "price_feed_tokenUsdPrice")]
    fn token_usd_price(&self, at: Option<BlockHash>) -> Result<Option<u32>>;

    #[rpc(name = "price_feed_tokenUsdPriceFromContract")]
    fn token_usd_price_from_contract(&self, at: Option<BlockHash>) -> Result<Option<u32>>;
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

impl<C, Block> PriceFeedApi<<Block as BlockT>::Hash> for PriceFeed<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: PriceFeedRuntimeApi<Block>,
{
    fn token_usd_price(&self, at: Option<<Block as BlockT>::Hash>) -> Result<Option<u32>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.token_usd_price(&at).map_err(|e| RpcError {
            code: ErrorCode::ServerError(1),
            message: "Unable to query price.".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }

    fn token_usd_price_from_contract(
        &self,
        at: Option<<Block as BlockT>::Hash>,
    ) -> Result<Option<u32>> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.token_usd_price_from_contract(&at)
            .map_err(|e| RpcError {
                code: ErrorCode::ServerError(2),
                message: "Unable to query price from contract.".into(),
                data: Some(format!("{:?}", e).into()),
            })
    }
}
