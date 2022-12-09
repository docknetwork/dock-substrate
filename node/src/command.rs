// Copyright 2017-2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

use std::convert::TryInto;

use super::bench::*;
use crate::{
    chain_spec,
    cli::{Cli, Subcommand},
    service::{self, new_partial},
};
use frame_benchmarking_cli::{BenchmarkCmd, ExtrinsicFactory, SUBSTRATE_REFERENCE_HARDWARE};
use sc_cli::{ChainSpec, RuntimeVersion, SubstrateCli};
use sc_service::{Configuration, PartialComponents};
use sp_keyring::Sr25519Keyring;

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Dock Node".into()
    }

    fn impl_version() -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn executable_name() -> String {
        env!("CARGO_PKG_NAME").into()
    }

    fn description() -> String {
        env!("CARGO_PKG_DESCRIPTION").into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "support.dock.io".into()
    }

    fn copyright_start_year() -> i32 {
        2017
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "" | "dev" => Box::new(chain_spec::development_config()),
            "local_testnet" => Box::new(chain_spec::local_testnet_config()),
            "devnet" => Box::new(chain_spec::pos_devnet_config()),
            "testnet" => Box::new(chain_spec::pos_testnet_config()),
            "mainnet" => Box::new(chain_spec::pos_mainnet_config()),
            path => Box::new(chain_spec::ChainSpec::from_json_file(
                std::path::PathBuf::from(path),
            )?),
        })
    }

    fn native_runtime_version(_: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        &dock_runtime::VERSION
    }
}

/// Enhances given function by setting default ss58 version based on supplied config before execution.
fn with_default_ss58<R>(f: impl FnOnce(Configuration) -> R) -> impl FnOnce(Configuration) -> R {
    |config: Configuration| {
        sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(
            config
                .chain_spec
                .properties()
                .get("ss58Format")
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|val| val.try_into().ok())
                        .expect("Invalid `ss58Format`")
                })
                .unwrap_or_else(dock_runtime::SS58Prefix::get) as u16,
        ));

        f(config)
    }
}

/// Parse and run command line arguments
pub fn run() -> sc_cli::Result<()> {
    let cli = Cli::from_args();
    sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(
        dock_runtime::SS58Prefix::get() as u16,
    ));

    match &cli.subcommand {
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(with_default_ss58(|config| {
                cmd.run(config.chain_spec, config.network)
            }))
        }
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(with_default_ss58(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    import_queue,
                    ..
                } = new_partial(&config, &cli)?;
                Ok((cmd.run(client, import_queue), task_manager))
            }))
        }
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(with_default_ss58(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = service::new_partial(&config, &cli)?;
                Ok((cmd.run(client, config.database), task_manager))
            }))
        }
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(with_default_ss58(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = new_partial(&config, &cli)?;
                Ok((cmd.run(client, config.chain_spec), task_manager))
            }))
        }
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(with_default_ss58(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    import_queue,
                    ..
                } = new_partial(&config, &cli)?;
                Ok((cmd.run(client, import_queue), task_manager))
            }))
        }
        Some(Subcommand::Key(cmd)) => cmd.run(&cli),
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(with_default_ss58(|config| {
                // Remove Frontier offchain db
                let frontier_database_config = sc_service::DatabaseSource::RocksDb {
                    path: service::frontier_database_dir(&config),
                    cache_size: 0,
                };
                cmd.run(frontier_database_config)?;
                cmd.run(config.database)
            }))
        }
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(with_default_ss58(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    backend,
                    ..
                } = service::new_partial(&config, &cli)?;
                let aux_revert = Box::new(move |client, _, blocks| {
                    sc_finality_grandpa::revert(client, blocks)?;
                    Ok(())
                });
                Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
            }))
        }
        Some(Subcommand::Benchmark(cmd)) => {
            let runner = cli.create_runner(cmd)?;

            runner.sync_run(with_default_ss58(|config| {
                // This switch needs to be in the client, since the client decides
                // which sub-commands it wants to support.
                match cmd {
                    BenchmarkCmd::Pallet(cmd) => {
                        if !cfg!(feature = "runtime-benchmarks") {
                            return Err(
                                "Runtime benchmarking wasn't enabled when building the node. \
							You can enable it with `--features runtime-benchmarks`."
                                    .into(),
                            );
                        }

                        cmd.run::<dock_runtime::Block, service::ExecutorDispatch>(config)
                    }
                    BenchmarkCmd::Block(cmd) => {
                        let PartialComponents { client, .. } = service::new_partial(&config, &cli)?;
                        cmd.run(client)
                    }
                    BenchmarkCmd::Storage(cmd) => {
                        let PartialComponents {
                            client, backend, ..
                        } = service::new_partial(&config, &cli)?;
                        let db = backend.expose_db();
                        let storage = backend.expose_storage();

                        cmd.run(config, client, db, storage)
                    }
                    BenchmarkCmd::Overhead(cmd) => {
                        let PartialComponents { client, .. } = service::new_partial(&config, &cli)?;
                        let ext_builder = RemarkBuilder::new(client.clone());

                        cmd.run(
                            config,
                            client,
                            inherent_benchmark_data()?,
                            Vec::new(),
                            &ext_builder,
                        )
                    }
                    BenchmarkCmd::Extrinsic(cmd) => {
                        let PartialComponents { client, .. } = service::new_partial(&config, &cli)?;
                        // Register the *Remark* and *TKA* builders.
                        let ext_factory = ExtrinsicFactory(vec![
                            Box::new(RemarkBuilder::new(client.clone())),
                            Box::new(TransferKeepAliveBuilder::new(
                                client.clone(),
                                Sr25519Keyring::Alice.to_account_id(),
                                dock_runtime::ExistentialDeposit::get(),
                            )),
                        ]);

                        cmd.run(client, inherent_benchmark_data()?, Vec::new(), &ext_factory)
                    }
                    BenchmarkCmd::Machine(cmd) => {
                        cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone())
                    }
                }
            }))
        }
        Some(Subcommand::Inspect(cmd)) => {
            let runner = cli.create_runner(cmd)?;

            runner.sync_run(with_default_ss58(|config| {
                cmd.run::<dock_runtime::Block, dock_runtime::RuntimeApi, service::ExecutorDispatch>(
                    config,
                )
            }))
        }
        None => {
            let runner = cli.create_runner(&cli.run.base)?;
            runner.run_node_until_exit(with_default_ss58(|config| async move {
                service::new_full(config, &cli).map_err(sc_cli::Error::Service)
            }))
        }
    }
}
