use sc_cli::RunCmd;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Cli {
    #[structopt(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[structopt(long = "instdev")]
    /// Skip normal block validation logic and produce blocks instantly whenever
    /// transactions enter the transaction pool. Must be accompanied by the --dev
    /// flag.
    pub instdev: bool,
    
    // this RunCmd is only populated when subcommand is None
    #[structopt(flatten)]
    pub run: RunCmd,
}

/// Possible subcommands of the main binary.
#[derive(Debug, StructOpt)]
pub enum Subcommand {
    /// A set of base subcommands handled by `sc_cli`.
    #[structopt(flatten)]
    Base(sc_cli::Subcommand),

    /// The custom benchmark subcommmand benchmarking runtime pallets.
    #[structopt(name = "benchmark", about = "Benchmark runtime pallets.")]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
}
