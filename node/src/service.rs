//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use std::path::PathBuf;

use beefy_gadget::BeefyParams;
// use beefy_primitives::KEY_TYPE;
use dock_runtime::{self, opaque::Block, RuntimeApi};
use fc_mapping_sync::{MappingSyncWorker, SyncStrategy};
use fc_rpc::{
    EthTask, OverrideHandle, RuntimeApiStorageOverride, SchemaV1Override, StorageOverride,
};
use fc_rpc_core::types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool};
use fp_storage::EthereumStorageSchema;
use futures::StreamExt;
use sc_cli::SubstrateCli;
use sc_client_api::{BlockBackend, BlockchainEvents, ExecutorProvider};
use sc_consensus_babe::{BabeBlockImport, BabeLink, BabeParams};
use sc_consensus_slots::{BackoffAuthoringOnFinalizedHeadLagging, SlotProportion};
pub use sc_executor::NativeElseWasmExecutor;
use sc_finality_grandpa::{
    FinalityProofProvider as GrandpaFinalityProofProvider, SharedVoterState,
};
use sc_network_common::service::NetworkEventStream;
use sc_rpc::SubscriptionTaskExecutor;
use sc_service::{error::Error as ServiceError, BasePath, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_api::ProvideRuntimeApi;
use sp_core::{Encode, Pair};
use sp_runtime::{generic, traits::Block as BlockT};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use substrate_frame_rpc_system::AccountNonceApi;

use crate::cli::Cli;

// Our native executor instance.
pub struct ExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        dock_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        dock_runtime::native_version()
    }
}

pub type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
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

pub fn open_frontier_backend(path: PathBuf) -> Result<Arc<fc_db::Backend<Block>>, String> {
    Ok(Arc::new(fc_db::Backend::<Block>::new(
        &fc_db::DatabaseSettings {
            source: sc_client_db::DatabaseSource::RocksDb {
                path,
                cache_size: 0,
            },
        },
    )?))
}

pub fn new_partial(
    config: &Configuration,
    _cli: &Cli,
) -> Result<
    sc_service::PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        sc_consensus::DefaultImportQueue<Block, FullClient>,
        sc_transaction_pool::FullPool<Block, FullClient>,
        (
            BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
            sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
            BabeLink<Block>,
            Option<Telemetry>,
            // Frontier specific
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

    let telemetry = get_telemetry_worker_from_config(&config)?;
    let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
        config.wasm_method,
        config.default_heap_pages,
        config.max_runtime_instances,
        config.runtime_cache_size,
    );

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            &config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
        )?;
    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());
    let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );

    let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
        client.clone(),
        &(client.clone() as Arc<_>),
        select_chain.clone(),
        telemetry.as_ref().map(|x| x.handle()),
    )?;

    let frontier_backend = open_frontier_backend(frontier_database_dir(config))?;

    let (babe_block_import, babe_link) = sc_consensus_babe::block_import(
        sc_consensus_babe::configuration(&*client)?,
        grandpa_block_import.clone(),
        client.clone(),
    )?;
    let slot_duration = sc_consensus_babe::configuration(&*client)?.slot_duration();

    let import_queue = sc_consensus_babe::import_queue(
        babe_link.clone(),
        babe_block_import.clone(),
        Some(Box::new(grandpa_block_import)),
        client.clone(),
        select_chain.clone(),
        move |_, ()| async move {
            let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

            let slot =
                sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                    *timestamp,
                    slot_duration,
                );
            let uncles =
                sp_authorship::InherentDataProvider::<<Block as BlockT>::Header>::check_inherents();

            Ok((timestamp, slot, uncles))
        },
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
        // inherent_data_providers,
        other: (
            babe_block_import,
            grandpa_link,
            babe_link,
            telemetry,
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
        // inherent_data_providers,
        other:
            (
                block_import,
                grandpa_link,
                babe_link,
                mut telemetry,
                //pending_transactions,
                filter_pool,
                frontier_backend,
            ),
    } = new_partial(&config, cli)?;

    if let Some(url) = &config.keystore_remote {
        return Err(ServiceError::Other(format!(
            "Error hooking up remote keystore for {}: Remote Keystore not supported.",
            url
        )));
    }

    let fee_history_cache: FeeHistoryCache = Arc::new(Mutex::new(BTreeMap::new()));
    let fee_history_cache_limit: FeeHistoryCacheLimit = 10;

    // Note: GrandPa is pushed before the Polkadot-specific protocols. This doesn't change
    // anything in terms of behaviour, but makes the logs more consistent with the other
    // Substrate nodes.
    let grandpa_protocol_name = sc_finality_grandpa::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("Genesis block exists; qed"),
        &config.chain_spec,
    );
    config
        .network
        .extra_sets
        .push(sc_finality_grandpa::grandpa_peers_set_config(
            grandpa_protocol_name.clone(),
        ));

    let beefy_protocol_name = beefy_gadget::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("Genesis block exists; qed"),
        &config.chain_spec,
    );
    config
        .network
        .extra_sets
        .push(beefy_gadget::beefy_peers_set_config(
            beefy_protocol_name.clone(),
        ));

    let role = config.role.clone();
    // if the node isn't actively participating in consensus then it doesn't
    // need a keystore, regardless of which protocol we use below.
    let keystore = role
        .is_authority()
        .then(|| keystore_container.sync_keystore());

    let (block_import, beefy_voter_links, beefy_rpc_links) =
        beefy_gadget::beefy_block_import_and_links(block_import, backend.clone(), client.clone());

    let justification_stream = grandpa_link.justification_stream();
    let shared_authority_set = grandpa_link.shared_authority_set().clone();
    let shared_voter_state = SharedVoterState::empty();
    let finality_proof_provider = GrandpaFinalityProofProvider::new_for_service(
        backend.clone(),
        Some(shared_authority_set.clone()),
    );

    let (network, system_rpc_tx, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            // on_demand: None,
            // TODO
            warp_sync: None,
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

    // Below code is taken from frontier template
    let mut overrides_map = BTreeMap::new();
    overrides_map.insert(
        EthereumStorageSchema::V1,
        Box::new(SchemaV1Override::new(client.clone()))
            as Box<dyn StorageOverride<_> + Send + Sync>,
    );
    let overrides = Arc::new(OverrideHandle {
        schemas: overrides_map,
        fallback: Box::new(RuntimeApiStorageOverride::new(client.clone())),
    });
    let block_data_cache = Arc::new(fc_rpc::EthBlockDataCacheTask::new(
        task_manager.spawn_handle(),
        overrides.clone(),
        50,
        50,
        config.prometheus_registry().cloned(),
    ));

    let is_authority = role.is_authority();
    let force_authoring = config.force_authoring;

    let name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();
    let target_gas_price = cli.run.target_gas_price;

    let grandpa_shared_voter_state = shared_voter_state.clone();

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        let select_chain = select_chain.clone();
        let fee_history_cache = fee_history_cache.clone();
        let overrides = overrides.clone();
        let network = network.clone();
        let keystore = keystore_container.sync_keystore();
        let chain_spec = config.chain_spec.cloned_box();

        let babe_config = babe_link.config().clone();
        let shared_epoch_changes = babe_link.epoch_changes().clone();

        // Frontier specific
        let filter_pool = filter_pool.clone();
        let backend = backend.clone();
        let frontier_backend = frontier_backend.clone();
        let max_past_logs = cli.run.max_past_logs;

        Box::new(
            move |deny_unsafe, subscription_task_executor: SubscriptionTaskExecutor| {
                let deps = crate::rpc::FullDeps {
                    client: client.clone(),
                    pool: pool.clone(),
                    graph: pool.pool().clone(),
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
                        finality_provider: finality_proof_provider.clone(),
                        subscription_executor: subscription_task_executor.clone(),
                    },
                    block_data_cache: block_data_cache.clone(),
                    is_authority,
                    network: network.clone(),
                    fee_history_cache: fee_history_cache.clone(),
                    fee_history_cache_limit,
                    filter_pool: filter_pool.clone(),
                    frontier_backend: frontier_backend.clone(),
                    backend: backend.clone(),
                    max_past_logs,
                    target_gas_price,
                    beefy: crate::rpc::BeefyDeps {
                        beefy_finality_proof_stream: beefy_rpc_links
                            .from_voter_justif_stream
                            .clone(),
                        beefy_best_block_stream: beefy_rpc_links
                            .from_voter_best_beefy_stream
                            .clone(),
                        subscription_executor: subscription_task_executor.clone(),
                    },
                    overrides: overrides.clone(),
                };

                crate::rpc::create_full(deps, subscription_task_executor).map_err(Into::into)
            },
        )
    };

    task_manager.spawn_essential_handle().spawn(
        "frontier-mapping-sync-worker",
        Some("frontier"),
        MappingSyncWorker::new(
            client.import_notification_stream(),
            Duration::from_millis(dock_runtime::SLOT_DURATION),
            client.clone(),
            backend.clone(),
            frontier_backend.clone(),
            3,
            0,
            SyncStrategy::Normal,
        )
        .for_each(|()| futures::future::ready(())),
    );

    // Start the BEEFY bridge gadget.
    task_manager.spawn_essential_handle().spawn_blocking(
        "beefy-gadget",
        None,
        beefy_gadget::start_beefy_gadget(BeefyParams {
            client: client.clone(),
            backend: backend.clone(),
            runtime: client.clone(),
            key_store: keystore.clone(),
            network: network.clone(),
            links: beefy_voter_links,
            min_block_delta: 6,
            prometheus_registry: prometheus_registry.clone(),
            protocol_name: beefy_protocol_name,
        }),
    );

    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: network.clone(),
        keystore: keystore_container.sync_keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: rpc_extensions_builder,
        config: config,
        client: client.clone(),
        backend: backend.clone(),
        // on_demand: None,
        // warp_sync: None,
        //
        system_rpc_tx,
        telemetry: telemetry.as_mut(),
    })?;

    // Spawn Frontier EthFilterApi maintenance task.
    if let Some(filter_pool) = filter_pool {
        // Each filter is allowed to stay in the pool for 100 blocks.
        const FILTER_RETAIN_THRESHOLD: u64 = 100;
        task_manager.spawn_essential_handle().spawn(
            "frontier-filter-pool",
            Some("frontier"),
            EthTask::filter_pool_task(Arc::clone(&client), filter_pool, FILTER_RETAIN_THRESHOLD),
        );
    }

    // Spawn Frontier FeeHistory cache maintenance task.
    task_manager.spawn_essential_handle().spawn(
        "frontier-fee-history",
        None,
        EthTask::fee_history_task(
            client.clone(),
            overrides.clone(),
            fee_history_cache,
            fee_history_cache_limit,
        ),
    );

    if is_authority {
        // Spawn Babe proposer
        let mut proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool,
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );
        proposer_factory.set_default_block_size_limit(6 * 1024 * 1024 + 512);

        let can_author_with =
            sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

        let backoff_authoring_blocks = Some(BackoffAuthoringOnFinalizedHeadLagging::default());

        let client_clone = client.clone();
        let slot_duration = sc_consensus_babe::configuration(&*client)?.slot_duration();

        let babe_config = BabeParams {
            justification_sync_link: network.clone(),
            create_inherent_data_providers: move |parent, ()| {
                let client_clone = client_clone.clone();
                async move {
                    let uncles = sc_consensus_uncles::create_uncles_inherent_data_provider(
                        &*client_clone,
                        parent,
                    )?;

                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    let slot =
						sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
							*timestamp,
							slot_duration,
						);

                    let storage_proof =
                        sp_transaction_storage_proof::registration::new_data_provider(
                            &*client_clone,
                            &parent,
                        )?;

                    Ok((timestamp, slot, uncles, storage_proof))
                }
            },
            max_block_proposal_slot_portion: None,
            keystore: keystore_container.sync_keystore(),
            client: client.clone(),
            select_chain,
            env: proposer_factory,
            block_import,
            sync_oracle: network.clone(),
            force_authoring,
            backoff_authoring_blocks,
            babe_link,
            can_author_with,
            // TODO: Revisit SlotProportion value
            block_proposal_slot_portion: SlotProportion::new(0.5),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
        };

        let babe = sc_consensus_babe::start_babe(babe_config)?;
        task_manager.spawn_essential_handle().spawn_blocking(
            "babe-proposer",
            Some("block-authoring"),
            babe,
        );

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
            Some("authority-discovery"),
            authority_discovery_worker.run(),
        );
    }

    let grandpa_config = sc_finality_grandpa::Config {
        protocol_name: grandpa_protocol_name,
        // FIXME #1578 make this available through chainspec
        gossip_duration: Duration::from_millis(333),
        justification_period: 512,
        name: Some(name),
        observer_enabled: false,
        local_role: role,
        keystore: keystore.clone(),
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
            Some("grandpa-voter"),
            sc_finality_grandpa::run_grandpa_voter(grandpa_config)?,
        );
    }

    network_starter.start_network();
    Ok(task_manager)
}

/// Fetch the nonce of the given `account` from the chain state.
///
/// Note: Should only be used for tests.
pub fn fetch_nonce(client: &FullClient, account: sp_core::sr25519::Pair) -> u32 {
    let best_hash = client.chain_info().best_hash;
    client
        .runtime_api()
        .account_nonce(&generic::BlockId::Hash(best_hash), account.public().into())
        .expect("Fetching account nonce works; qed")
}

/// Create a transaction using the given `call`.
///
/// The transaction will be signed by `sender`. If `nonce` is `None` it will be fetched from the
/// state of the best block.
///
/// Note: Should only be used for tests.
pub fn create_extrinsic(
    client: &FullClient,
    sender: sp_core::sr25519::Pair,
    function: impl Into<dock_runtime::Call>,
    nonce: Option<u32>,
) -> dock_runtime::UncheckedExtrinsic {
    let function = function.into();
    let genesis_hash = client
        .block_hash(0)
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");
    let best_hash = client.chain_info().best_hash;
    let nonce = nonce.unwrap_or_else(|| fetch_nonce(client, sender.clone()));

    let tip = 0;
    let extra = (
        frame_system::CheckSpecVersion::<dock_runtime::Runtime>::new(),
        frame_system::CheckTxVersion::<dock_runtime::Runtime>::new(),
        frame_system::CheckGenesis::<dock_runtime::Runtime>::new(),
        frame_system::CheckEra::<dock_runtime::Runtime>::from(generic::Era::Immortal),
        frame_system::CheckNonce::<dock_runtime::Runtime>::from(nonce),
        frame_system::CheckWeight::<dock_runtime::Runtime>::new(),
        dock_runtime::CustomChargeTransactionPayment(
            pallet_transaction_payment::ChargeTransactionPayment::from(tip),
        ),
        token_migration::OnlyMigrator::<dock_runtime::Runtime>::new(),
    );

    let raw_payload = dock_runtime::SignedPayload::from_raw(
        function.clone(),
        extra.clone(),
        (
            dock_runtime::VERSION.spec_version,
            dock_runtime::VERSION.transaction_version,
            genesis_hash,
            best_hash,
            (),
            (),
            (),
            (),
        ),
    );
    let signature = raw_payload.using_encoded(|e| sender.sign(e));

    dock_runtime::UncheckedExtrinsic::new_signed(
        function,
        sp_runtime::AccountId32::from(sender.public()).into(),
        dock_runtime::Signature::Sr25519(signature),
        extra,
    )
}
