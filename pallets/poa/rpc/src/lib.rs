pub use self::gen_client::Client as PoAClient;
use codec::Codec;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
pub use poa::runtime_api::PoAApi as PoARuntimeApi;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, MaybeDisplay, MaybeFromStr},
};
use std::sync::Arc;

#[rpc]
pub trait PoAApi<BlockHash, AccountId, Balance> {
    /// Return account address of treasury. The account address can then be used to query the
    /// chain for balance
    #[rpc(name = "poa_treasuryAccount")]
    fn treasury_account(&self, at: Option<BlockHash>) -> Result<AccountId>;

    /// Return free balance of treasury account. In the context of PoA, only free balance makes
    /// sense for treasury. But just in case, to check all kinds of balance (locked, reserved, etc),
    /// get the account address with above call and query the chain.
    #[rpc(name = "poa_treasuryBalance")]
    fn treasury_balance(&self, at: Option<BlockHash>) -> Result<Balance>;
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

impl<C, Block, AccountId, Balance> PoAApi<<Block as BlockT>::Hash, AccountId, Balance>
    for PoA<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: PoARuntimeApi<Block, AccountId, Balance>,
    AccountId: Codec + MaybeDisplay + MaybeFromStr,
    Balance: Codec + MaybeDisplay + MaybeFromStr,
{
    fn treasury_account(&self, at: Option<<Block as BlockT>::Hash>) -> Result<AccountId> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.get_treasury_account(&at).map_err(|e| RpcError {
            code: ErrorCode::ServerError(1),
            message: "Unable to query treasury account address.".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }

    fn treasury_balance(&self, at: Option<<Block as BlockT>::Hash>) -> Result<Balance> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied assume the best block.
            self.client.info().best_hash));
        api.get_treasury_balance(&at).map_err(|e| RpcError {
            code: ErrorCode::ServerError(2),
            message: "Unable to query treasury account balance.".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }
}
