//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use dock_runtime::{self, opaque::Block, RuntimeApi};
use fc_consensus::FrontierBlockImport;
use fc_mapping_sync::MappingSyncWorker;
use fc_rpc::EthTask;
use fc_rpc_core::types::{FilterPool, PendingTransactions};
use futures::StreamExt;
use sc_cli::SubstrateCli;
use sc_client_api::{BlockchainEvents, ExecutorProvider, RemoteBackend};
use sc_consensus_aura::{AuraBlockImport, ImportQueueParams, SlotProportion, StartAuraParams};
use sc_executor::native_executor_instance;
pub use sc_executor::NativeExecutor;
use sc_finality_grandpa::{
    FinalityProofProvider as GrandpaFinalityProofProvider, SharedVoterState,
};
use sc_service::{error::Error as ServiceError, BasePath, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
use sp_inherents::InherentDataProviders;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

pub fn open_frontier_backend(config: &Configuration) -> Result<Arc<fc_db::Backend<Block>>, String> {
    let config_dir = config
        .base_path
        .as_ref()
        .map(|base_path| base_path.config_dir(config.chain_spec.id()))
        .unwrap_or_else(|| {
            BasePath::from_project("", "", &crate::cli::Cli::executable_name())
                .config_dir(config.chain_spec.id())
        });
    let database_dir = config_dir.join("frontier").join("db");

    Ok(Arc::new(fc_db::Backend::<Block>::new(
        &fc_db::DatabaseSettings {
            source: fc_db::DatabaseSettingsSrc::RocksDb {
                path: database_dir,
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
            AuraBlockImport<
                Block,
                FullClient,
                FrontierBlockImport<
                    Block,
                    sc_finality_grandpa::GrandpaBlockImport<
                        FullBackend,
                        Block,
                        FullClient,
                        FullSelectChain,
                    >,
                    FullClient,
                >,
                AuraPair,
            >,
            sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
            PendingTransactions,
            Option<FilterPool>,
            Arc<fc_db::Backend<Block>>,
            Option<Telemetry>,
        ),
    >,
    ServiceError,
> {
    if config.keystore_remote.is_some() {
        return Err(ServiceError::Other(format!(
            "Remote Keystores are not supported."
        )));
    }

    let inherent_data_providers = sp_inherents::InherentDataProviders::new();

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

    let frontier_block_import = FrontierBlockImport::new(
        grandpa_block_import.clone(),
        client.clone(),
        frontier_backend.clone(),
    );

    let aura_block_import =
        AuraBlockImport::<_, _, _, AuraPair>::new(frontier_block_import, client.clone());

    let import_queue =
        sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(ImportQueueParams {
            slot_duration: sc_consensus_aura::slot_duration(&*client)?,
            block_import: aura_block_import.clone(),
            justification_import: Some(Box::new(grandpa_block_import)),
            client: client.clone(),
            inherent_data_providers: inherent_data_providers.clone(),
            spawner: &task_manager.spawn_essential_handle(),
            registry: config.prometheus_registry(),
            can_author_with: sp_consensus::CanAuthorWithNativeVersion::new(
                client.executor().clone(),
            ),
            check_for_equivocation: Default::default(),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
        })?;

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
            aura_block_import,
            grandpa_link,
            pending_transactions,
            filter_pool,
            frontier_backend,
            telemetry,
        ),
    })
}

/// Builds a new service for a full client.
pub fn new_full(mut config: Configuration) -> Result<TaskManager, ServiceError> {
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
                pending_transactions,
                filter_pool,
                frontier_backend,
                mut telemetry,
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

    let subscription_task_executor =
        sc_rpc::SubscriptionTaskExecutor::new(task_manager.spawn_handle());

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        let network = network.clone();
        let pending = pending_transactions.clone();
        let filter_pool = filter_pool.clone();
        let frontier_backend = frontier_backend.clone();

        Box::new(move |deny_unsafe, _| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
                deny_unsafe,
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
            };

            crate::rpc::create_full(deps, subscription_task_executor.clone())
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
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool,
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let can_author_with =
            sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

        let backoff_authoring_blocks: Option<()> = None;

        let aura = sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _>(
            StartAuraParams {
                slot_duration: sc_consensus_aura::slot_duration(&*client)?,
                client: client.clone(),
                select_chain,
                block_import,
                proposer_factory,
                sync_oracle: network.clone(),
                inherent_data_providers: inherent_data_providers.clone(),
                force_authoring,
                backoff_authoring_blocks,
                keystore: keystore_container.sync_keystore(),
                can_author_with,
                block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
                telemetry: telemetry.as_ref().map(|x| x.handle()),
            },
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

    let aura_block_import =
        AuraBlockImport::<_, _, _, AuraPair>::new(grandpa_block_import.clone(), client.clone());

    let import_queue =
        sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(ImportQueueParams {
            slot_duration: sc_consensus_aura::slot_duration(&*client)?,
            block_import: aura_block_import.clone(),
            justification_import: Some(Box::new(grandpa_block_import)),
            client: client.clone(),
            inherent_data_providers: InherentDataProviders::new(),
            spawner: &task_manager.spawn_essential_handle(),
            registry: config.prometheus_registry(),
            can_author_with: sp_consensus::NeverCanAuthor,
            check_for_equivocation: Default::default(),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
        })?;

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
