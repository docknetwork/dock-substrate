//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use std::sync::Arc;

use beefy_gadget_rpc::{Beefy, BeefyApiServer};
use dock_runtime::{
    opaque::Block, AccountId, Balance, BlockNumber, Hash, Index, TransactionConverter,
};
use fc_rpc::{EthBlockDataCacheTask, EthDevSigner, EthSigner, OverrideHandle};
use fc_rpc_core::types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool};
use jsonrpsee::RpcModule;
use pallet_mmr_rpc::{Mmr, MmrApiServer};
use sc_client_api::{
    backend::{AuxStore, Backend, StateBackend, StorageProvider},
    client::BlockchainEvents,
};
use sc_consensus_babe::{BabeConfiguration, Epoch};
use sc_consensus_babe_rpc::{Babe, BabeApiServer};
use sc_consensus_epochs::SharedEpochChanges;
use sc_finality_grandpa::{
    FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet, SharedVoterState,
};
use sc_finality_grandpa_rpc::{Grandpa, GrandpaApiServer};
use sc_network::NetworkService;
use sc_rpc::SubscriptionTaskExecutor;
pub use sc_rpc_api::DenyUnsafe;
use sc_sync_state_rpc::{SyncState, SyncStateApiServer};
use sc_transaction_pool::{ChainApi, Pool};
use sc_transaction_pool_api::TransactionPool;
use snowbridge_basic_channel_rpc::{BasicChannel, BasicChannelApiServer};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;
use sp_consensus_babe::BabeApi;
use sp_keystore::SyncCryptoStorePtr;

/// Extra dependencies for BABE.
pub struct BabeDeps {
    /// BABE protocol config.
    pub babe_config: BabeConfiguration,
    /// BABE pending epoch changes.
    pub shared_epoch_changes: SharedEpochChanges<Block, Epoch>,
    /// The keystore that manages the keys of the node.
    pub keystore: SyncCryptoStorePtr,
}

/// Extra dependencies for GRANDPA
pub struct GrandpaDeps<B> {
    /// Voting round info.
    pub shared_voter_state: SharedVoterState,
    /// Authority set info.
    pub shared_authority_set: SharedAuthoritySet<Hash, BlockNumber>,
    /// Receives notifications about justification events from Grandpa.
    pub justification_stream: GrandpaJustificationStream<Block>,
    /// Executor to drive the subscription manager in the Grandpa RPC handler.
    pub subscription_executor: sc_rpc::SubscriptionTaskExecutor,
    /// Finality proof provider.
    pub finality_provider: Arc<FinalityProofProvider<B, Block>>,
}

/// Full client dependencies.
pub struct FullDeps<C, P, B, SC, A: ChainApi> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Graph pool instance.
    pub graph: Arc<Pool<A>>,
    /// The SelectChain Strategy
    pub select_chain: SC,
    /// A copy of the chain spec.
    pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
    /// Whether to deny unsafe calls
    pub deny_unsafe: DenyUnsafe,
    /// BABE specific dependencies.
    pub babe: BabeDeps,
    /// GRANDPA specific dependencies.
    pub grandpa: GrandpaDeps<B>,
    /// The Node authority flag
    pub is_authority: bool,
    /// Network service
    pub network: Arc<NetworkService<Block, Hash>>,
    /// Fee history cache.
    pub fee_history_cache: FeeHistoryCache,
    /// Fee history cache limit.
    pub fee_history_cache_limit: FeeHistoryCacheLimit,
    /// EthFilterApi pool.
    pub filter_pool: Option<FilterPool>,
    /// Frontier backend.
    pub frontier_backend: Arc<fc_db::Backend<Block>>,
    /// Backend.
    pub backend: Arc<B>,
    /// Maximum number of logs in a query.
    pub max_past_logs: u32,
    /// Target gas price.
    pub target_gas_price: u32,
    /// BEEFY specific dependencies.
    pub beefy: BeefyDeps,
    /// Block data cache.
    pub block_data_cache: Arc<EthBlockDataCacheTask<Block>>,
    /// Ethereum data access overrides.
    pub overrides: Arc<OverrideHandle<Block>>,
}

use beefy_gadget::notification::{BeefyBestBlockStream, BeefyVersionedFinalityProofStream};
/// Dependencies for BEEFY
pub struct BeefyDeps {
    /// Receives notifications about signed commitment events from BEEFY.
    pub beefy_finality_proof_stream: BeefyVersionedFinalityProofStream<Block>,
    /// Receives notifications about best block events from BEEFY.
    pub beefy_best_block_stream: BeefyBestBlockStream<Block>,
    /// Executor to drive the subscription manager in the BEEFY RPC handler.
    pub subscription_executor: sc_rpc::SubscriptionTaskExecutor,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P, B, SC, A>(
    deps: FullDeps<C, P, B, SC, A>,
    subscription_executor: SubscriptionTaskExecutor,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    B: Backend<Block> + Send + Sync + 'static,
    B::State: StateBackend<sp_runtime::traits::HashFor<Block>>,
    C: ProvideRuntimeApi<Block> + StorageProvider<Block, B> + AuxStore,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    C: BlockchainEvents<Block>,
    C: Send + Sync + 'static,
    C::Api: BabeApi<Block>,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Index>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: poa_rpc::PoARuntimeApi<Block, AccountId, Balance>,
    C::Api: pallet_mmr_rpc::MmrRuntimeApi<Block, <Block as sp_runtime::traits::Block>::Hash>,
    C::Api: price_feed_rpc::PriceFeedRuntimeApi<Block>,
    C::Api: fiat_filter_rpc::FiatFeeRuntimeApi<Block, Balance>,
    C::Api: staking_rewards_rpc::StakingRewardsRuntimeApi<Block, Balance>,
    C::Api: core_mods_rpc::CoreModsRuntimeApi<Block, dock_runtime::Runtime>,
    C::Api: BlockBuilder<Block>,
    C::Api: fp_rpc::EthereumRuntimeRPCApi<Block>,
    C::Api: fp_rpc::ConvertTransactionRuntimeApi<Block>,
    P: TransactionPool<Block = Block> + 'static,
    SC: SelectChain<Block> + 'static,
    A: ChainApi<Block = Block> + 'static,
{
    use core_mods_rpc::{CoreMods, CoreModsApiServer};
    use fiat_filter_rpc::{FiatFee, FiatFeeApiServer};
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use poa_rpc::{PoA, PoAApiServer};
    use price_feed_rpc::{PriceFeed, PriceFeedApiServer};
    use staking_rewards_rpc::{StakingRewards, StakingRewardsApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    use fc_rpc::{
        Eth, EthApiServer, EthFilter, EthFilterApiServer, EthPubSub, EthPubSubApiServer, Net,
        NetApiServer, Web3, Web3ApiServer,
    };

    let mut io = RpcModule::new(());
    let FullDeps {
        client,
        graph,
        pool,
        select_chain,
        chain_spec,
        deny_unsafe,
        babe,
        grandpa,
        is_authority,
        network,
        filter_pool,
        frontier_backend,
        backend,
        max_past_logs,
        fee_history_cache,
        target_gas_price: _,
        fee_history_cache_limit,
        block_data_cache,
        beefy,
        overrides,
    } = deps;

    let BabeDeps {
        keystore,
        babe_config,
        shared_epoch_changes,
    } = babe;

    let GrandpaDeps {
        shared_voter_state,
        shared_authority_set,
        justification_stream,
        finality_provider,
        ..
    } = grandpa;

    io.merge(System::new(client.clone(), pool.clone(), deny_unsafe).into_rpc())?;

    io.merge(TransactionPayment::new(client.clone()).into_rpc())?;

    // RPC calls for PoA pallet
    io.merge(PoA::new(client.clone()).into_rpc())?;

    // RPC calls for Price Feed pallet
    io.merge(PriceFeed::new(client.clone()).into_rpc())?;

    // RPC calls for Staking rewards pallet
    io.merge(StakingRewards::new(client.clone()).into_rpc())?;

    // RPC calls for core mods pallet
    io.merge(<CoreMods<_, _> as CoreModsApiServer<
        _,
        core_mods_rpc::SerializableConfigWrapper<dock_runtime::Runtime>,
    >>::into_rpc(CoreMods::new(client.clone())))?;

    io.merge(
        Babe::new(
            client.clone(),
            shared_epoch_changes.clone(),
            keystore,
            babe_config,
            select_chain,
            deny_unsafe,
        )
        .into_rpc(),
    )?;

    io.merge(
        Grandpa::new(
            subscription_executor.clone(),
            shared_authority_set.clone(),
            shared_voter_state,
            justification_stream,
            finality_provider,
        )
        .into_rpc(),
    )?;

    io.merge(
        SyncState::new(
            chain_spec,
            client.clone(),
            shared_authority_set,
            shared_epoch_changes,
        )?
        .into_rpc(),
    )?;

    let mut signers = Vec::new();
    if true {
        signers.push(Box::new(EthDevSigner::new()) as Box<dyn EthSigner>);
    }

    io.merge(
        Eth::new(
            client.clone(),
            pool.clone(),
            graph,
            Some(TransactionConverter),
            network.clone(),
            signers,
            overrides.clone(),
            frontier_backend.clone(),
            // Is authority.
            is_authority,
            block_data_cache.clone(),
            fee_history_cache,
            fee_history_cache_limit,
            10,
        )
        .into_rpc(),
    )?;

    if let Some(filter_pool) = filter_pool {
        io.merge(
            EthFilter::new(
                client.clone(),
                frontier_backend,
                filter_pool,
                500_usize, // max stored filters
                max_past_logs,
                block_data_cache,
            )
            .into_rpc(),
        )?;
    }

    io.merge(
        Net::new(
            client.clone(),
            network.clone(),
            // Whether to format the `peer_count` response as Hex (default) or not.
            true,
        )
        .into_rpc(),
    )?;

    io.merge(Mmr::new(client.clone()).into_rpc())?;

    io.merge(Web3::new(client.clone()).into_rpc())?;

    io.merge(
        EthPubSub::new(
            pool,
            client.clone(),
            network.clone(),
            subscription_executor,
            overrides,
        )
        .into_rpc(),
    )?;

    io.merge(
        Beefy::<Block>::new(
            beefy.beefy_finality_proof_stream,
            beefy.beefy_best_block_stream,
            beefy.subscription_executor,
        )?
        .into_rpc(),
    )?;

    io.merge(FiatFee::new(client.clone()).into_rpc())?;

    if let Some(basic_channel_rpc) = backend
        .offchain_storage()
        .map(|storage| BasicChannel::<_>::new(storage).into_rpc())
    {
        log::info!("Starting basic channel RPC");
        io.merge(basic_channel_rpc)?;
    }

    Ok(io)
}
