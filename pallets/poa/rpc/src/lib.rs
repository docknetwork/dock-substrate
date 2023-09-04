use codec::Codec;
use core::fmt::Debug;
pub use dock_poa::runtime_api::PoAApi as PoARuntimeApi;
use jsonrpsee::{
    core::{async_trait, Error as JsonRpseeError, RpcResult},
    proc_macros::rpc,
    types::{error::CallError, ErrorObject},
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, MaybeDisplay, MaybeFromStr},
};
use std::sync::Arc;

#[rpc(server, client)]
pub trait PoAApi<BlockHash, AccountId, Balance> {
    /// Return account address of treasury. The account address can then be used to query the
    /// chain for balance
    #[method(name = "poa_treasuryAccount")]
    async fn treasury_account(&self, at: Option<BlockHash>) -> RpcResult<AccountId>;

    /// Return free balance of treasury account. In the context of PoA, only free balance makes
    /// sense for treasury. But just in case, to check all kinds of balance (locked, reserved, etc),
    /// get the account address with above call and query the chain.
    #[method(name = "poa_treasuryBalance")]
    async fn treasury_balance(&self, at: Option<BlockHash>) -> RpcResult<Balance>;
}

/// A struct that implements the [`PoAApi`].
pub struct PoA<C, P> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<P>,
}

impl<C, P> PoA<C, P> {
    /// Create new `PoA` with the given reference to the client.
    pub fn new(client: Arc<C>) -> Self {
        PoA {
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
impl<C, Block, AccountId, Balance> PoAApiServer<<Block as BlockT>::Hash, AccountId, Balance>
    for PoA<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: PoARuntimeApi<Block, AccountId, Balance>,
    AccountId: Codec + MaybeDisplay + MaybeFromStr,
    Balance: Codec + MaybeDisplay + MaybeFromStr,
{
    async fn treasury_account(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<AccountId> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.get_treasury_account(&at)
            .map_err(RuntimeError)
            .map_err(Into::into)
    }

    async fn treasury_balance(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<Balance> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.get_treasury_balance(&at)
            .map_err(RuntimeError)
            .map_err(Into::into)
    }
}
