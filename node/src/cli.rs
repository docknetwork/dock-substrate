#[allow(missing_docs)]
#[derive(Debug, clap::Parser)]
pub struct RunCmd {
    #[allow(missing_docs)]
    #[clap(flatten)]
    pub base: sc_cli::RunCmd,

    /// Maximum number of logs in a query.
    #[clap(long, default_value = "10000")]
    pub max_past_logs: u32,

    // The dynamic-fee pallet target gas price set by block author
    #[clap(long, default_value = "1")]
    pub target_gas_price: u32,

    #[clap(long, default_value = "0")]
    pub node_id: u8,
}

#[derive(Debug, clap::Parser)]
pub struct Cli {
    #[clap(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[clap(flatten)]
    pub run: RunCmd,
}

/// Possible subcommands of the main binary.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Key utilities for the cli.
    #[clap(subcommand)]
    Key(sc_cli::KeySubcommand),

    /// The custom benchmark subcommmand benchmarking runtime pallets.
    // #[clap(name = "benchmark", about = "Benchmark runtime pallets.")]
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),

    /// The custom inspect subcommmand for decoding blocks and extrinsics.
    Inspect(node_inspect::cli::InspectCmd),
}
