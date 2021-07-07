# Dock Blockchain Node

[Rust Docs](https://docknetwork.github.io/dock-substrate/dock_runtime).
[Javascript Client](https://github.com/docknetwork/sdk).

The dock blockchain serves as registry for [Decentralized Identifiers](https://www.w3.org/TR/did-core) and for revocations of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model).

## Quickstart

Docker can be used to quickly spin up a node (may require sudo):

```
docker run -p 9944:9944 -p 30333:30333 docknetwork/dock-substrate:latest --chain ./cspec/knox_raw.json --ws-external
             |            |                       |                         |                              |
             |     Expose p2p port                |                 Join the mainnet                       |
             |                                    |                                                        |
    Expose websocket port          Use the node image from dockerhub                     Listen for rpc over websocket
```

The above command will run a mainnet node. To run a testnet node, use the chainspec `knox_test_raw.json` in place of `knox_raw.json`
and image `docknetwork/dock-substrate:testnet` in place of `docknetwork/dock-substrate:latest` in the above command.

To view possible command line arguments:

```
docker run docknetwork/dock-substrate --help
```

## Build

To build the node executable yourself, you'll need to install the following dependencies.

```bash
# Install Rust.
curl https://sh.rustup.rs -sSf | sh

# Ensure rust nightly version pinned by ./rust-toolchain is installed.
rustup update nightly

# Install the wasm32-unknown-unknown target for the rust version pinned by ./rust-toolchain.
rustup target add wasm32-unknown-unknown --toolchain nightly
```

The project is known to build with cargo 1.51.0 and rust 1.51.0. Upgrade to these versions or higher if unable to build

Now you can build the node binary.

```bash
cargo build --release
```

Above command will build a node with ss58 prefix 42 which is for dev nodes. To build node for testnet or mainnet, use the 
features `testnet` and `mainnet` respectively as below

```bash
cargo build --release --features testnet
```

The `spec_name` with the above command will be `dock-pos-test-runtime` and ss58 prefix will be 21. 

```bash
cargo build --release --features mainnet
```

The `spec_name` with the above command will be `dock-pos-main-runtime` and ss58 prefix will be 22.

Running without any features will result in `spec_name` of `dock-dev-runtime`

### Building a node for testing staking, governance

Testing staking, elections, governance, etc capabilities requires quite some time as the duration of corresponding 
operations varies between a few hours to few days. Eg. an epoch is 3 hours long, era is 12 hours long, it takes 7 days to unbond, 
a new referendum is launched every 20 days, voting lasts for 15 days, and so on. To test these features in a reasonable time, these 
durations need to be small. Such a node can be built by using feature `small_durations` as shown below. This feature can be combined 
with feature `testnet` or `mainnet`. 

```
cargo build --release --features small_durations
```

### Building a node for faster block production
For **testing** with SDK, faster block production is needed, i.e. < 1sec. Use the `fastblock` feature to achieve that.  

```bash
cargo build --release --features fastblock
```

### Building Docker image

To build image for testnet node, run the following from the repository's root

```bash
docker build --build-arg features='--features testnet' .
```

To build image for mainnet node, run the following from the repository's root

```bash
docker build --build-arg features='--features mainnet' .
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.

## Releases
The testnet and mainnet codebases are tagged as `testnet` and `mainnet` respectively. On the releases page, you will only 
find mainnet releases. Similarly, the docker images corresponding to testnet and mainnet are tagged as `testnet` and `mainnet` 
respectively, and you can find pull them as `docker pull docknetwork/dock-substrate:testnet` or `docker pull docknetwork/dock-substrate:mainnet`

## Recipes

```
# Build and run unit tests.
cargo test --all

# Build and run a node in local development node for testing.
cargo run -- --dev

# Clear chain state after running the local development node.
cargo run -- purge-chain --dev

# View available command line options.
cargo run -- --help

# Incase block finalisation stalls for some reason, exporting the blocks, purging the chain and importing the blocks fixes it
# Make sure node is stopped before running followig commands. The `pruning mode` is by default `archive`

# Export blocks to file blocks.bin
./target/<debug or release>/dock-node export-blocks --binary --chain=<chain spec> --base-path=<data directory of the node> [--pruning=<pruning mode>] blocks.bin

# Purge chain
./target/<debug or release>/dock-node purge-chain --chain=<chain spec> --base-path=<data directory of the node>

# Import blocks from file blocks.bin
./target/<debug or release>/dock-node import-blocks --binary --chain=<chain spec> --base-path=<data directory of the node> [--pruning=<pruning mode>] blocks.bin 
```

## Polkadot-js UI

The [polkadot-js UI](https://polkadot.js.org/apps) UI can be used to interact with the dock network through a locally running node. 
Some custom types will need to be specified in the `Settings > Developer` section of the UI. The definitions for these types 
can currently be found in the [types.json](types.json) file.
