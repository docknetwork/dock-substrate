//! Substrate Node Template CLI library.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

mod chain_spec;
mod service;
mod cli;
mod command;

fn main() -> sc_cli::Result<()> {
    command::run()
}
