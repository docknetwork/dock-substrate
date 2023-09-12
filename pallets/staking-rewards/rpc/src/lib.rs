use codec::Codec;
use core::fmt::Debug;
pub use dock_staking_rewards::runtime_api::StakingRewardsApi as StakingRewardsRuntimeApi;
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
pub trait StakingRewardsApi<BlockHash, Balance> {
    /// Emission reward 1 year from now given the currently staked funds and issuance.
    /// Depends on the reward curve, decay percentage and remaining emission supply.
    #[method(name = "staking_rewards_yearlyEmission")]
    async fn yearly_emission(
        &self,
        total_staked: Balance,
        total_issuance: Balance,
        at: Option<BlockHash>,
    ) -> RpcResult<Balance>;

    /// Maximum emission reward for 1 year from now.
    /// Depends on decay percentage and remaining emission supply.
    #[method(name = "staking_rewards_maxYearlyEmission")]
    async fn max_yearly_emission(&self, at: Option<BlockHash>) -> RpcResult<Balance>;
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

/// A struct that implements the [`StakingRewardsApi`].
pub struct StakingRewards<C, P> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<P>,
}

impl<C, P> StakingRewards<C, P> {
    /// Create new `StakingRewards` with the given reference to the client.
    pub fn new(client: Arc<C>) -> Self {
        StakingRewards {
            client,
            _marker: Default::default(),
        }
    }
}

#[async_trait]
impl<C, Block, Balance> StakingRewardsApiServer<<Block as BlockT>::Hash, Balance>
    for StakingRewards<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: StakingRewardsRuntimeApi<Block, Balance>,
    Balance: Codec + MaybeDisplay + MaybeFromStr + Send + 'static,
{
    async fn yearly_emission(
        &self,
        total_staked: Balance,
        total_issuance: Balance,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Balance> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(|| self.client.info().best_hash));
        api.yearly_emission(&at, total_staked, total_issuance)
            .map_err(RuntimeError)
            .map_err(Into::into)
    }

    async fn max_yearly_emission(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<Balance> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(|| self.client.info().best_hash));
        api.max_yearly_emission(&at)
            .map_err(RuntimeError)
            .map_err(Into::into)
    }
}
