//! Substrate Node Template CLI library.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

mod chain_spec;
#[macro_use]
mod service;
mod cli;

use sc_cli::VersionInfo;

fn main() -> Result<(), cli::error::Error> {
    let version = VersionInfo {
        name: "Dock Testnet Node",
        commit: env!("VERGEN_SHA_SHORT"),
        version: env!("CARGO_PKG_VERSION"),
        executable_name: "dock-testnet",
        author: "Dock.io",
        description: "A full node for Dock testnet",
        support_url: "dock.io",
    };

    cli::run(std::env::args(), cli::Exit, version)
}
