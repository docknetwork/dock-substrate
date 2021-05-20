# Dock Blockchain Node

[Rust Docs](https://docknetwork.github.io/dock-substrate/dock_runtime).
[Javascript Client](https://github.com/docknetwork/sdk).

The dock blockchain serves as registry for [Decentralized Identifiers](https://www.w3.org/TR/did-core) and for revocations of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model).

## Quickstart

Docker can be used to quickly spin up a node (may require sudo):

```
docker run -p 9944:9944 -p 30333:30333 docknetwork/dock-substrate:latest --chain ./cspec/vulcan_raw.json --ws-external
             |            |                       |                         |                              |
             |     Expose p2p port                |                 Join the mainnet                       |
             |                                    |                                                        |
    Expose websocket port          Use the node image from dockerhub                     Listen for rpc over websocket
```

The above command will run a mainnet node. To run a testnet node, use the chainspec `danforth_raw.json` in place of `vulcan_raw.json`
and image `docknetwork/dock-substrate:testnet` in place of `docknetwork/dock-substrate:latest` in the above command.

To view possible command line arguments:

```
docker run docknetwork/dock-substrate --help
```

## Building

To build the node executable yourself, you'll need to install the following dependencies.

```bash
# Install Rust.
curl https://sh.rustup.rs -sSf | sh

# Ensure rust nightly version pinned by ./rust-toolchain is installed.
rustup update nightly

# Install the wasm32-unknown-unknown target for the rust version pinned by ./rust-toolchain.
rustup target add wasm32-unknown-unknown --toolchain nightly
```

Now you can build the node binary.

```bash
cargo build --release
```

Above command will build a node with ss58 prefix 42 which is for dev nodes. To build node for testnet or mainnet, use the 
features `testnet` and `mainnet` respectively as below

```bash
cargo build --release --features testnet
```

The `spec_name` with the above command will be `dock-test-runtime` and ss58 prefix will be 21. 

```bash
cargo build --release --features mainnet
```

The `spec_name` with the above command will be `dock-main-runtime` and ss58 prefix will be 22.

Running without any features will result in `spec_name` of `dock-dev-runtime`

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
