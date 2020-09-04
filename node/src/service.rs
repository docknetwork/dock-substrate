//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use dock_testnet_runtime::{self, opaque::Block, RuntimeApi};
use futures::stream::StreamExt;
use sc_client_api::{ExecutorProvider, RemoteBackend};
use sc_executor::native_executor_instance;
pub use sc_executor::NativeExecutor;
use sc_finality_grandpa::{
    FinalityProofProvider as GrandpaFinalityProofProvider, SharedVoterState,
};
use sc_network::config::DummyFinalityProofRequestBuilder;
use sc_service::{error::Error as ServiceError, Configuration, PartialComponents, TaskManager};
use sc_transaction_pool::txpool;
use sp_consensus::block_validation::BlockAnnounceValidator;
use sp_consensus::block_validation::Validation;
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
use sp_inherents::InherentDataProviders;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

// Our native executor instance.
native_executor_instance!(
    pub Executor,
    dock_testnet_runtime::api::dispatch,
    dock_testnet_runtime::native_version,
    frame_benchmarking::benchmarking::HostFunctions,
);

type FullClient = sc_service::TFullClient<Block, RuntimeApi, Executor>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub fn new_partial(
    config: &Configuration,
) -> Result<
    PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        sp_consensus::DefaultImportQueue<Block, FullClient>,
        sc_transaction_pool::FullPool<Block, FullClient>,
        (
            sc_finality_grandpa::GrandpaBlockImport<
                FullBackend,
                Block,
                FullClient,
                FullSelectChain,
            >,
            sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
        ),
    >,
    ServiceError,
> {
    let inherent_data_providers = sp_inherents::InherentDataProviders::new();

    let (client, backend, keystore, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, Executor>(&config)?;
    let client = Arc::new(client);

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
    );

    let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
        client.clone(),
        &(client.clone() as Arc<_>),
        select_chain.clone(),
    )?;

    let aura_block_import = sc_consensus_aura::AuraBlockImport::<_, _, _, AuraPair>::new(
        grandpa_block_import.clone(),
        client.clone(),
    );

    let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _, _>(
        sc_consensus_aura::slot_duration(&*client)?,
        aura_block_import,
        Some(Box::new(grandpa_block_import.clone())),
        None,
        client.clone(),
        inherent_data_providers.clone(),
        &task_manager.spawn_handle(),
        config.prometheus_registry(),
        sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
    )?;

    Ok(PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore,
        select_chain,
        transaction_pool,
        inherent_data_providers,
        other: (grandpa_block_import, grandpa_link),
    })
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
    let PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore,
        select_chain,
        transaction_pool,
        inherent_data_providers,
        other: (block_import, grandpa_link),
    } = new_partial(&config)?;

    let finality_proof_provider =
        GrandpaFinalityProofProvider::new_for_service(backend.clone(), client.clone());

    let (network, network_status_sinks, system_rpc_tx, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            on_demand: None,
            block_announce_validator_builder: None,
            finality_proof_request_builder: None,
            finality_proof_provider: Some(finality_proof_provider.clone()),
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            backend.clone(),
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
        );
    }

    let role = config.role.clone();
    let force_authoring = config.force_authoring;
    let name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();
    let telemetry_connection_sinks = sc_service::TelemetryConnectionSinks::default();

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();

        Box::new(move |deny_unsafe, _| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
                deny_unsafe,
            };

            crate::rpc::create_full(deps)
        })
    };

    sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: network.clone(),
        client: client.clone(),
        keystore: keystore.clone(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        telemetry_connection_sinks: telemetry_connection_sinks.clone(),
        rpc_extensions_builder,
        on_demand: None,
        remote_blockchain: None,
        backend,
        network_status_sinks,
        system_rpc_tx,
        config,
    })?;

    if role.is_authority() {
        let proposer = sc_basic_authorship::ProposerFactory::new(
            client.clone(),
            transaction_pool,
            prometheus_registry.as_ref(),
        );

        let can_author_with =
            sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

        let aura = sc_consensus_aura::start_aura::<_, _, _, _, _, AuraPair, _, _, _>(
            sc_consensus_aura::slot_duration(&*client)?,
            client.clone(),
            select_chain,
            block_import,
            proposer,
            network.clone(),
            inherent_data_providers.clone(),
            force_authoring,
            keystore.clone(),
            can_author_with,
        )?;

        // the AURA authoring task is considered essential, i.e. if it
        // fails we take down the service with it.
        task_manager
            .spawn_essential_handle()
            .spawn_blocking("aura", aura);
    }

    // if the node isn't actively participating in consensus then it doesn't
    // need a keystore, regardless of which protocol we use below.
    let keystore = if role.is_authority() {
        Some(keystore as sp_core::traits::BareCryptoStorePtr)
    } else {
        None
    };

    let grandpa_config = sc_finality_grandpa::Config {
        // FIXME #1578 make this available through chainspec
        gossip_duration: Duration::from_millis(333),
        justification_period: 512,
        name: Some(name),
        observer_enabled: false,
        keystore,
        is_authority: role.is_network_authority(),
    };

    if enable_grandpa {
        // start the full GRANDPA voter
        // NOTE: non-authorities could run the GRANDPA observer protocol, but at
        // this point the full voter should provide better guarantees of block
        // and vote data availability than the observer. The observer has not
        // been tested extensively yet and having most nodes in a network run it
        // could lead to finality stalls.
        let grandpa_config = sc_finality_grandpa::GrandpaParams {
            config: grandpa_config,
            link: grandpa_link,
            network,
            inherent_data_providers,
            telemetry_on_connect: Some(telemetry_connection_sinks.on_connect_stream()),
            voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state: SharedVoterState::empty(),
        };

        // the GRANDPA voter task is considered infallible, i.e.
        // if it fails we take down the service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            sc_finality_grandpa::run_grandpa_voter(grandpa_config)?,
        );
    } else {
        sc_finality_grandpa::setup_disabled_grandpa(client, &inherent_data_providers, network)?;
    }

    network_starter.start_network();
    Ok(task_manager)
}

/// Builds a new service for a light client.
pub fn new_light(config: Configuration) -> Result<TaskManager, ServiceError> {
    let (client, backend, keystore, mut task_manager, on_demand) =
        sc_service::new_light_parts::<Block, RuntimeApi, Executor>(&config)?;

    let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
        config.transaction_pool.clone(),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
        on_demand.clone(),
    ));

    let grandpa_block_import = sc_finality_grandpa::light_block_import(
        client.clone(),
        backend.clone(),
        &(client.clone() as Arc<_>),
        Arc::new(on_demand.checker().clone()) as Arc<_>,
    )?;
    let finality_proof_import = grandpa_block_import.clone();
    let finality_proof_request_builder =
        finality_proof_import.create_finality_proof_request_builder();

    let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _, _>(
        sc_consensus_aura::slot_duration(&*client)?,
        grandpa_block_import,
        None,
        Some(Box::new(finality_proof_import)),
        client.clone(),
        InherentDataProviders::new(),
        &task_manager.spawn_handle(),
        config.prometheus_registry(),
        sp_consensus::NeverCanAuthor,
    )?;

    let finality_proof_provider =
        GrandpaFinalityProofProvider::new_for_service(backend.clone(), client.clone());

    let (network, network_status_sinks, system_rpc_tx, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            on_demand: Some(on_demand.clone()),
            block_announce_validator_builder: None,
            finality_proof_request_builder: Some(finality_proof_request_builder),
            finality_proof_provider: Some(finality_proof_provider),
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            backend.clone(),
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
        );
    }

    sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        remote_blockchain: Some(backend.remote_blockchain()),
        transaction_pool,
        task_manager: &mut task_manager,
        on_demand: Some(on_demand),
        rpc_extensions_builder: Box::new(|_, _| ()),
        telemetry_connection_sinks: sc_service::TelemetryConnectionSinks::default(),
        config,
        client,
        keystore,
        backend,
        network,
        network_status_sinks,
        system_rpc_tx,
    })?;

    network_starter.start_network();

    Ok(task_manager)
}

/// Builds a new service for a full client.
pub fn new_instdev(config: Configuration) -> Result<TaskManager, ServiceError> {
    let inherent_data_providers = InherentDataProviders::new();

    inherent_data_providers
        .register_provider(sp_timestamp::InherentDataProvider)
        .map_err(Into::into)
        .map_err(sp_consensus::Error::InherentData)?;

    // // aura provider implicitly adds timestamp provider
    // inherent_data_providers
    //     .register_provider(sc_consensus_aura::InherentDataProvider::new(1))
    //     .map_err(Into::into)
    //     .map_err(sp_consensus::Error::InherentData)?;

    let (client, backend, keystore, mut task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, Executor>(&config)?;
    let client = Arc::new(client);

    // Initialize seed for signing transaction using off-chain workers
    #[cfg(feature = "ocw")]
    {
        let dev_seed = config.dev_key_seed.clone();
        if let Some(seed) = dev_seed {
            keystore
                .write()
                .insert_ephemeral_from_seed_by_type::<runtime::offchain_demo::crypto::Pair>(
                    &seed,
                    runtime::offchain_demo::KEY_TYPE,
                )
                .expect("Dev Seed should always succeed.");
        }
    }

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
    );

    let import_queue = sc_consensus_manual_seal::import_queue(
        Box::new(client.clone()),
        &task_manager.spawn_handle(),
        config.prometheus_registry(),
    );

    let (network, network_status_sinks, system_rpc_tx, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            on_demand: None,
            block_announce_validator_builder: Some(Box::new(|_| Box::new(EveryBlockIsPerfect))),
            finality_proof_request_builder: Some(Box::new(DummyFinalityProofRequestBuilder)),
            finality_proof_provider: Some(Arc::new(())),
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            backend.clone(),
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
        );
    }

    let is_authority = config.role.is_authority();
    let prometheus_registry = config.prometheus_registry().cloned();
    let telemetry_connection_sinks = sc_service::TelemetryConnectionSinks::default();

    sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network,
        client: client.clone(),
        keystore,
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        telemetry_connection_sinks,
        rpc_extensions_builder: Box::new(|_, _| ()),
        on_demand: None,
        remote_blockchain: None,
        backend,
        network_status_sinks,
        system_rpc_tx,
        config,
    })?;

    if is_authority {
        let proposer = sc_basic_authorship::ProposerFactory::new(
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
        );

        // create blocks as soon as they enter the pool
        let tpool: Arc<txpool::Pool<_>> = transaction_pool.pool().clone();
        let p = tpool.clone();
        let idp = inherent_data_providers.clone();
        let commands_stream =
            tpool
                .validated_pool()
                .import_notification_stream()
                .map(move |_: sp_core::H256| {
                    let id = idp.create_inherent_data().unwrap();
                    dbg!(id.len());
                    // assert_eq!(idp.create_inherent_data().unwrap().len(), 2);
                    // assert_eq!(idp.create_inherent_data().unwrap().len(), 2);
                    assert!(p.validated_pool().status().ready != 0);
                    sc_consensus_manual_seal::EngineCommand::SealNewBlock {
                        create_empty: false,
                        finalize: true,
                        parent_hash: None,
                        sender: None,
                    }
                });

        let authorship_future = crate::manual_seal_custom::run_manual_seal(
            Box::new(client.clone()),
            proposer,
            client,
            tpool,
            commands_stream,
            select_chain,
            inherent_data_providers,
        );

        task_manager
            .spawn_essential_handle()
            .spawn_blocking("instant-seal", authorship_future);
    };

    network_starter.start_network();

    Ok(task_manager)
}

pub struct EveryBlockIsPerfect;

impl<B: sp_runtime::traits::Block> BlockAnnounceValidator<B> for EveryBlockIsPerfect {
    fn validate(&mut self, _h: &B::Header, _d: &[u8]) -> Result<Validation, Box<dyn Error + Send>> {
        Ok(Validation::Success { is_new_best: true })
    }
}

// issue 1 Timestamp not getting set
//   Initial solution is to add the timestamp inherent data provider or the Aura inherent data
//   provider, which implies timestamp.
//   The error sometimes reappears after producing several blocks but I don't know why.
// issue 2 transaction priority too low
//   I think this one is caused by multiple transactions from the same account accumulating in the
//   same pool. Since two txns from the same account exist, their priorities are compared and one is
//   dropped.
//
// I think instant_seal is reciving a signal to create a new block before the extrinsic is in the pool.
// It then complains that the block is empty.
//
// Hypothesis 1:
//   Instant seal is triggered and attempts to read from pool before it transaction is added.
//   Future transactions are disallowed because there is already a transaction by that same
//   author in the pool.
//
//   possible: a race condition causes instant seal to sometimes pick up the transaction in time
//   so the the first few transactions sometimes work
//
// Observation:
//   Transactions are never commited to a block uness allow_empty it true.
//   Whan allow empty is true, transactions blocks are produced, but very slowly.
//   If transaction submission is sped up by not waiting for finalization,
//   timestamp and aura slot inherent dont stop getting included in blocks.
//   since both timestamp and slot are checked on_finalize, processing the
//   block results in a panic. The block is never finalized so old transactions
//   never leave the transaction pool. Sinse old transactions are still in the pool
//   submitting new ones with the same account results in
//     Error: 1014: Priority is too low: (9223372037331108274 vs 9223372037281108177): The
//     transaction has too low priority to replace another transaction already in the pool.
