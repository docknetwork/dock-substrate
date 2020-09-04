//! Substrate Node Template CLI library.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

mod chain_spec;
mod cli;
mod command;
mod manual_seal_custom;
mod rpc;
mod service;

fn main() -> sc_cli::Result<()> {
    command::run()
}
