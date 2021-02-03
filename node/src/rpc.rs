//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use std::{sync::Arc, fmt};

use dock_runtime::{opaque::Block, AccountId, Balance, BlockNumber, Hash, Index, TransactionConverter};
use sc_finality_grandpa::{
    FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet, SharedVoterState,
};
use sc_finality_grandpa_rpc::GrandpaRpcHandler;
use sc_rpc::SubscriptionTaskExecutor;
pub use sc_rpc_api::DenyUnsafe;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_transaction_pool::TransactionPool;
use sc_network::NetworkService;
use sc_client_api::{
    backend::{StorageProvider, Backend, StateBackend, AuxStore},
    client::BlockchainEvents
};
use jsonrpc_pubsub::manager::SubscriptionManager;
use fc_rpc_core::types::{PendingTransactions, FilterPool};

/// Extra dependencies for GRANDPA
pub struct GrandpaDeps<B> {
    /// Voting round info.
    pub shared_voter_state: SharedVoterState,
    /// Authority set info.
    pub shared_authority_set: SharedAuthoritySet<Hash, BlockNumber>,
    /// Receives notifications about justification events from Grandpa.
    pub justification_stream: GrandpaJustificationStream<Block>,
    /// Finality proof provider.
    pub finality_proof_provider: Arc<FinalityProofProvider<B, Block>>,
}

/// Full client dependencies.
pub struct FullDeps<C, P, B> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Whether to deny unsafe calls
    pub deny_unsafe: DenyUnsafe,
    /// GRANDPA specific dependencies.
    pub grandpa: GrandpaDeps<B>,
    /// The Node authority flag
    pub is_authority: bool,
    /// Network service
    pub network: Arc<NetworkService<Block, Hash>>,
    /// Ethereum pending transactions.
    pub pending_transactions: PendingTransactions,
    /// EthFilterApi pool.
    pub filter_pool: Option<FilterPool>,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P, B>(deps: FullDeps<C, P, B>, subscription_executor: SubscriptionTaskExecutor) -> jsonrpc_core::IoHandler<sc_rpc::Metadata>
where
    B: Backend<Block> + Send + Sync + 'static,
    B::State: StateBackend<sp_runtime::traits::HashFor<Block>>,
    // B::State: StateBackend<sp_runtime::traits::BlakeTwo256>,
    C: ProvideRuntimeApi<Block> + StorageProvider<Block, B> + AuxStore,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    C: BlockchainEvents<Block>,
    C: Send + Sync + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Index>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: poa_rpc::PoARuntimeApi<Block, AccountId, Balance>,
    C::Api: BlockBuilder<Block>,
    C::Api: fp_rpc::EthereumRuntimeRPCApi<Block>,
    <C::Api as sp_api::ApiErrorExt>::Error: fmt::Debug,
    P: TransactionPool<Block=Block> + 'static,
{
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApi};
    use poa_rpc::{PoA, PoAApi};
    use substrate_frame_rpc_system::{FullSystem, SystemApi};

    use fc_rpc::{
        EthApi, EthApiServer, EthFilterApi, EthFilterApiServer, NetApi, NetApiServer,
        EthPubSubApi, EthPubSubApiServer, Web3Api, Web3ApiServer, HexEncodedIdProvider
    };

    let mut io = jsonrpc_core::IoHandler::default();
    let FullDeps {
        client,
        pool,
        deny_unsafe,
        grandpa,
        is_authority,
        network,
        pending_transactions,
        filter_pool,
    } = deps;

    let GrandpaDeps {
        shared_voter_state,
        shared_authority_set,
        justification_stream,
        finality_proof_provider,
    } = grandpa;

    io.extend_with(SystemApi::to_delegate(FullSystem::new(
        client.clone(),
        pool.clone(),
        deny_unsafe,
    )));

    io.extend_with(TransactionPaymentApi::to_delegate(TransactionPayment::new(
        client.clone(),
    )));

    // RPC calls for PoA pallet
    io.extend_with(PoAApi::to_delegate(PoA::new(client.clone())));

    io.extend_with(sc_finality_grandpa_rpc::GrandpaApi::to_delegate(
        GrandpaRpcHandler::new(
            shared_authority_set,
            shared_voter_state,
            justification_stream,
            subscription_executor.clone(),
            finality_proof_provider,
        ),
    ));

    // Below code is taken from frontier template
    io.extend_with(
        EthApiServer::to_delegate(EthApi::new(
            client.clone(),
            pool.clone(),
            TransactionConverter,
            network.clone(),
            pending_transactions.clone(),
            vec![],
            is_authority,
        ))
    );

    if let Some(filter_pool) = filter_pool {
        io.extend_with(
            EthFilterApiServer::to_delegate(EthFilterApi::new(
                client.clone(),
                filter_pool.clone(),
                500 as usize, // max stored filters
            ))
        );
    }

    io.extend_with(
        NetApiServer::to_delegate(NetApi::new(
            client.clone(),
            network.clone(),
        ))
    );

    io.extend_with(
        Web3ApiServer::to_delegate(Web3Api::new(
            client.clone(),
        ))
    );

    io.extend_with(
        EthPubSubApiServer::to_delegate(EthPubSubApi::new(
            pool.clone(),
            client.clone(),
            network.clone(),
            SubscriptionManager::<HexEncodedIdProvider>::with_id_provider(
                HexEncodedIdProvider::default(),
                Arc::new(subscription_executor)
            ),
        ))
    );

    io
}
