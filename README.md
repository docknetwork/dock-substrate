# Dock Blockchain Node

[Rust Docs](https://docknetwork.github.io/dock-substrate/dock_testnet_runtime).
[Javascript Client](https://github.com/docknetwork/sdk).

The dock blockchain serves as registry for [Decentralized Identifiers](https://www.w3.org/TR/did-core) and for revocations of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model).

## Quickstart

Docker can be used to quickly spin up a node (may require sudo):

```
docker run -p 9933:9933 -p 30333:30333 docknetwork/dock-substrate --chain ./cspec/remdev-rc2.json --ws-external
             |            |                       |                      |                          |
             |     Expose p2p port                |              Join the testnet                   |
             |                                    |                                                 |
    Expose websocket port          Use the node image from dockerhub                   Listen for rpc over websocket
```

To view possible command line arguments:

```
docker run docknetwork/dock-substrate --help
```

## Hacking

To build the node executable yourself, you'll need to install the following dependencies.

```bash
# Install Rust.
curl https://sh.rustup.rs -sSf | sh

# Ensure rust nightly is installed and up to date.
rustup update nightly

# Ensure nightly can compile to wasm.
rustup target add wasm32-unknown-unknown --toolchain nightly
```

Now you can build the node binary.

```bash
cargo build --release
```

See [CONTRIBUTING.md](./contributing) for contribution guidelines.

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
```

## Polkadot-js UI

The [polkadot-js UI](https://polkadot.js.org/apps) UI can be used to interact with the dock network through a locally running node. Some custom types will need to be specified in the `Settings > Developer` section of the UI. The definitions for these types can currently be found in [types.json file](https://github.com/docknetwork/sdk/blob/master/src/types.json). (No guarantees that file will stay up to date though.)
