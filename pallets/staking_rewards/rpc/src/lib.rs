pub use self::gen_client::Client as StakingRewardsClient;
use codec::Codec;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, MaybeDisplay, MaybeFromStr},
};
pub use staking_rewards::runtime_api::StakingRewardsApi as StakingRewardsRuntimeApi;
use std::sync::Arc;

#[rpc]
pub trait StakingRewardsApi<BlockHash, Balance> {
    /// Emission reward 1 year from now given the currently staked funds and issuance.
    /// Depends on the reward curve, decay percentage and remaining emission supply.
    #[rpc(name = "staking_rewards_yearlyEmission")]
    fn yearly_emission(
        &self,
        total_staked: Balance,
        total_issuance: Balance,
        at: Option<BlockHash>,
    ) -> Result<Balance>;

    /// Maximum emission reward for 1 year from now.
    /// Depends on decay percentage and remaining emission supply.
    #[rpc(name = "staking_rewards_maxYearlyEmission")]
    fn max_yearly_emission(&self, at: Option<BlockHash>) -> Result<Balance>;
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

impl<C, Block, Balance> StakingRewardsApi<<Block as BlockT>::Hash, Balance>
    for StakingRewards<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: StakingRewardsRuntimeApi<Block, Balance>,
    Balance: Codec + MaybeDisplay + MaybeFromStr,
{
    fn yearly_emission(
        &self,
        total_staked: Balance,
        total_issuance: Balance,
        at: Option<<Block as BlockT>::Hash>,
    ) -> Result<Balance> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(|| self.client.info().best_hash));
        api.yearly_emission(&at, total_staked, total_issuance)
            .map_err(|e| RpcError {
                code: ErrorCode::ServerError(1),
                message: "Unable to get yearly inflation.".into(),
                data: Some(format!("{:?}", e).into()),
            })
    }

    fn max_yearly_emission(&self, at: Option<<Block as BlockT>::Hash>) -> Result<Balance> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(|| self.client.info().best_hash));
        api.max_yearly_emission(&at).map_err(|e| RpcError {
            code: ErrorCode::ServerError(2),
            message: "Unable to get max yearly inflation.".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }
}
