//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use dock_runtime::{self, opaque::Block, RuntimeApi};
use fc_mapping_sync::MappingSyncWorker;
use fc_rpc::EthTask;
use fc_rpc_core::types::{FilterPool, PendingTransactions};
use futures::StreamExt;
use sc_cli::SubstrateCli;
use sc_client_api::{BlockchainEvents, ExecutorProvider, RemoteBackend};
use sc_consensus_babe::{BabeBlockImport, BabeLink, BabeParams};
use sc_consensus_slots::{BackoffAuthoringOnFinalizedHeadLagging, SlotProportion};
use sc_executor::native_executor_instance;
pub use sc_executor::NativeExecutor;
use sc_finality_grandpa::{
    FinalityProofProvider as GrandpaFinalityProofProvider, SharedVoterState,
};
use sc_service::{error::Error as ServiceError, BasePath, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_inherents::InherentDataProviders;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::cli::Cli;

// Our native executor instance.
native_executor_instance!(
    pub Executor,
    dock_runtime::api::dispatch,
    dock_runtime::native_version,
    frame_benchmarking::benchmarking::HostFunctions,
);

type FullClient = sc_service::TFullClient<Block, RuntimeApi, Executor>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport =
    sc_finality_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>;

fn get_telemetry_worker_from_config(
    config: &Configuration,
) -> Result<Option<(TelemetryWorker, Telemetry)>, sc_telemetry::Error> {
    config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()
}

pub fn frontier_database_dir(config: &Configuration) -> std::path::PathBuf {
    let config_dir = config
        .base_path
        .as_ref()
        .map(|base_path| base_path.config_dir(config.chain_spec.id()))
        .unwrap_or_else(|| {
            BasePath::from_project("", "", &crate::cli::Cli::executable_name())
                .config_dir(config.chain_spec.id())
        });
    config_dir.join("frontier").join("db")
}

pub fn open_frontier_backend(config: &Configuration) -> Result<Arc<fc_db::Backend<Block>>, String> {
    Ok(Arc::new(fc_db::Backend::<Block>::new(
        &fc_db::DatabaseSettings {
            source: fc_db::DatabaseSettingsSrc::RocksDb {
                path: frontier_database_dir(&config),
                cache_size: 0,
            },
        },
    )?))
}

pub fn new_partial(
    config: &Configuration,
) -> Result<
    sc_service::PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        sp_consensus::DefaultImportQueue<Block, FullClient>,
        sc_transaction_pool::FullPool<Block, FullClient>,
        (
            BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
            sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
            BabeLink<Block>,
            Option<Telemetry>,
            // Frontier specific
            PendingTransactions,
            Option<FilterPool>,
            Arc<fc_db::Backend<Block>>,
        ),
    >,
    ServiceError,
> {
    if config.keystore_remote.is_some() {
        return Err(ServiceError::Other(format!(
            "Remote Keystores are not supported."
        )));
    }

    let inherent_data_providers = InherentDataProviders::new();

    let telemetry = get_telemetry_worker_from_config(&config)?;

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, Executor>(
            &config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        )?;
    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager.spawn_handle().spawn("telemetry", worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let pending_transactions: PendingTransactions = Some(Arc::new(Mutex::new(HashMap::new())));

    let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
    );

    let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
        client.clone(),
        &(client.clone() as Arc<_>),
        select_chain.clone(),
        telemetry.as_ref().map(|x| x.handle()),
    )?;

    let frontier_backend = open_frontier_backend(config)?;

    let (babe_block_import, babe_link) = sc_consensus_babe::block_import(
        sc_consensus_babe::Config::get_or_compute(&*client)?,
        grandpa_block_import.clone(),
        client.clone(),
    )?;

    let import_queue = sc_consensus_babe::import_queue(
        babe_link.clone(),
        babe_block_import.clone(),
        Some(Box::new(grandpa_block_import)),
        client.clone(),
        select_chain.clone(),
        inherent_data_providers.clone(),
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
        sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
        telemetry.as_ref().map(|x| x.handle()),
    )?;

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        inherent_data_providers,
        other: (
            babe_block_import,
            grandpa_link,
            babe_link,
            telemetry,
            pending_transactions,
            filter_pool,
            frontier_backend,
        ),
    })
}

/// Builds a new service for a full client.
pub fn new_full(mut config: Configuration, cli: &Cli) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        inherent_data_providers,
        other:
            (
                block_import,
                grandpa_link,
                babe_link,
                mut telemetry,
                pending_transactions,
                filter_pool,
                frontier_backend,
            ),
    } = new_partial(&config)?;

    if let Some(url) = &config.keystore_remote {
        return Err(ServiceError::Other(format!(
            "Error hooking up remote keystore for {}: Remote Keystore not supported.",
            url
        )));
    }

    config
        .network
        .extra_sets
        .push(sc_finality_grandpa::grandpa_peers_set_config());

    #[cfg(feature = "cli")]
    config.network.request_response_protocols.push(
        sc_finality_grandpa_warp_sync::request_response_config_for_chain(
            &config,
            task_manager.spawn_handle(),
            backend.clone(),
            grandpa_link.shared_authority_set().clone(),
        ),
    );

    let justification_stream = grandpa_link.justification_stream();
    let shared_authority_set = grandpa_link.shared_authority_set().clone();
    let shared_voter_state = SharedVoterState::empty();
    let finality_proof_provider = GrandpaFinalityProofProvider::new_for_service(
        backend.clone(),
        Some(shared_authority_set.clone()),
    );

    let (network, network_status_sinks, system_rpc_tx, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            on_demand: None,
            block_announce_validator_builder: None,
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
        );
    }

    let role = config.role.clone();
    let is_authority = role.is_authority();
    let force_authoring = config.force_authoring;
    let name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();

    let grandpa_shared_voter_state = shared_voter_state.clone();

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        let select_chain = select_chain.clone();
        let network = network.clone();
        let keystore = keystore_container.sync_keystore();
        let chain_spec = config.chain_spec.cloned_box();

        let babe_config = babe_link.config().clone();
        let shared_epoch_changes = babe_link.epoch_changes().clone();

        // Frontier specific
        let pending = pending_transactions.clone();
        let filter_pool = filter_pool.clone();
        let frontier_backend = frontier_backend.clone();
        let max_past_logs = cli.run.max_past_logs;

        Box::new(move |deny_unsafe, subscription_task_executor| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
                select_chain: select_chain.clone(),
                chain_spec: chain_spec.cloned_box(),
                deny_unsafe,
                babe: crate::rpc::BabeDeps {
                    babe_config: babe_config.clone(),
                    shared_epoch_changes: shared_epoch_changes.clone(),
                    keystore: keystore.clone(),
                },
                grandpa: crate::rpc::GrandpaDeps {
                    shared_voter_state: shared_voter_state.clone(),
                    shared_authority_set: shared_authority_set.clone(),
                    justification_stream: justification_stream.clone(),
                    finality_proof_provider: finality_proof_provider.clone(),
                },
                is_authority,
                network: network.clone(),
                pending_transactions: pending.clone(),
                filter_pool: filter_pool.clone(),
                backend: frontier_backend.clone(),
                max_past_logs,
            };

            crate::rpc::create_full(deps, subscription_task_executor)
        })
    };

    task_manager.spawn_essential_handle().spawn(
        "frontier-mapping-sync-worker",
        MappingSyncWorker::new(
            client.import_notification_stream(),
            Duration::new(6, 0),
            client.clone(),
            backend.clone(),
            frontier_backend.clone(),
        )
        .for_each(|()| futures::future::ready(())),
    );

    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: network.clone(),
        client: client.clone(),
        keystore: keystore_container.sync_keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_extensions_builder,
        on_demand: None,
        remote_blockchain: None,
        backend,
        network_status_sinks,
        system_rpc_tx,
        config,
        telemetry: telemetry.as_mut(),
    })?;

    // Spawn Frontier EthFilterApi maintenance task.
    if filter_pool.is_some() {
        // Each filter is allowed to stay in the pool for 100 blocks.
        const FILTER_RETAIN_THRESHOLD: u64 = 100;
        task_manager.spawn_essential_handle().spawn(
            "frontier-filter-pool",
            EthTask::filter_pool_task(
                Arc::clone(&client),
                filter_pool.unwrap(),
                FILTER_RETAIN_THRESHOLD,
            ),
        );
    }

    // Spawn Frontier pending transactions maintenance task (as essential, otherwise we leak).
    if pending_transactions.is_some() {
        const TRANSACTION_RETAIN_THRESHOLD: u64 = 5;
        task_manager.spawn_essential_handle().spawn(
            "frontier-pending-transactions",
            EthTask::pending_transaction_task(
                Arc::clone(&client),
                pending_transactions.unwrap(),
                TRANSACTION_RETAIN_THRESHOLD,
            ),
        );
    }

    if is_authority {
        // Spawn Babe proposer
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool,
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let can_author_with =
            sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

        let backoff_authoring_blocks = Some(BackoffAuthoringOnFinalizedHeadLagging::default());

        let babe_config = BabeParams {
            keystore: keystore_container.sync_keystore(),
            client: client.clone(),
            select_chain,
            env: proposer_factory,
            block_import,
            sync_oracle: network.clone(),
            inherent_data_providers: inherent_data_providers.clone(),
            force_authoring,
            backoff_authoring_blocks,
            babe_link,
            can_author_with,
            // TODO: Revisit SlotProportion value
            block_proposal_slot_portion: SlotProportion::new(0.5),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
        };

        let babe = sc_consensus_babe::start_babe(babe_config)?;
        task_manager
            .spawn_essential_handle()
            .spawn_blocking("babe-proposer", babe);

        // Spawn authority discovery module.

        let authority_discovery_role =
            sc_authority_discovery::Role::PublishAndDiscover(keystore_container.keystore());
        let dht_event_stream =
            network
                .event_stream("authority-discovery")
                .filter_map(|e| async move {
                    match e {
                        sc_network::Event::Dht(e) => Some(e),
                        _ => None,
                    }
                });
        let (authority_discovery_worker, _service) = sc_authority_discovery::new_worker_and_service(
            client.clone(),
            network.clone(),
            Box::pin(dht_event_stream),
            authority_discovery_role,
            prometheus_registry.clone(),
        );

        task_manager.spawn_handle().spawn(
            "authority-discovery-worker",
            authority_discovery_worker.run(),
        );
    }

    // if the node isn't actively participating in consensus then it doesn't
    // need a keystore, regardless of which protocol we use below.
    let keystore = if role.is_authority() {
        Some(keystore_container.sync_keystore())
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
        is_authority: role.is_authority(),
        telemetry: telemetry.as_ref().map(|x| x.handle()),
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
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state: grandpa_shared_voter_state,
        };

        // the GRANDPA voter task is considered infallible, i.e.
        // if it fails we take down the service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            sc_finality_grandpa::run_grandpa_voter(grandpa_config)?,
        );
    }

    network_starter.start_network();
    Ok(task_manager)
}

/// Builds a new service for a light client.
pub fn new_light(mut config: Configuration) -> Result<TaskManager, ServiceError> {
    let telemetry = get_telemetry_worker_from_config(&config)?;

    let (client, backend, keystore_container, mut task_manager, on_demand) =
        sc_service::new_light_parts::<Block, RuntimeApi, Executor>(
            &config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        )?;

    config
        .network
        .extra_sets
        .push(sc_finality_grandpa::grandpa_peers_set_config());

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
        config.transaction_pool.clone(),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
        on_demand.clone(),
    ));

    let mut telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager.spawn_handle().spawn("telemetry", worker.run());
        telemetry
    });

    let (grandpa_block_import, _) = sc_finality_grandpa::block_import(
        client.clone(),
        &(client.clone() as Arc<_>),
        select_chain.clone(),
        telemetry.as_ref().map(|x| x.handle()),
    )?;

    let (babe_block_import, babe_link) = sc_consensus_babe::block_import(
        sc_consensus_babe::Config::get_or_compute(&*client)?,
        grandpa_block_import.clone(),
        client.clone(),
    )?;

    let import_queue = sc_consensus_babe::import_queue(
        babe_link,
        babe_block_import,
        Some(Box::new(grandpa_block_import)),
        client.clone(),
        select_chain.clone(),
        InherentDataProviders::new(),
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
        sp_consensus::NeverCanAuthor,
        telemetry.as_ref().map(|x| x.handle()),
    )?;

    let (network, network_status_sinks, system_rpc_tx, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            on_demand: Some(on_demand.clone()),
            block_announce_validator_builder: None,
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
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
        config,
        client,
        keystore: keystore_container.sync_keystore(),
        backend,
        network,
        network_status_sinks,
        system_rpc_tx,
        telemetry: telemetry.as_mut(),
    })?;

    network_starter.start_network();

    Ok(task_manager)
}
