# PoS upgrade
As there is no way to change consensus algorithm from Aura to Babe through a forkless upgrade, we will fork the chain with 
a process [re-genesis](https://github.com/olegnn/substrate/issues/7458), i.e. we will start a new chain with new 
genesis, but the state (and not the blocks) of the old chain (PoA) will be included in the new chain's genesis so that account balances, 
contracts, DIDs, etc are not lost. This new genesis will also include the PoA chain's last block hash. The new chain-will have 
new `spec_name` so that a client can simultaneously connect to both chains (we will be hosting a PoA chain for a while). Below 
are the steps needed for re-genesis
1. Short-circuit epoch of PoA chain so that pending rewards are given to validators and treasury.
2. Disable emission rewards in PoA module so that emission stops
3. Disable access to all important modules that can meaningfully change the state as seen [here](https://github.com/docknetwork/dock-substrate/blob/pre-brick-chain/runtime/src/lib.rs#L721).
4. Dump the state of the chain to a JSON file with [this script](https://github.com/docknetwork/sdk/blob/master/scripts/dump_state.js). This is done only to compare state with the new chain.
5. Brick the chain, i.e. the chain will not produce any block and can't be used anymore. This is done by setting the wasm code to empty bytes (using `setCodeWithoutChecks`).
6. Take the chain's last block hash and put in the `chain_spec.rs` to make the new genesis have the PoA chain's last block.
7. Use the [fork-off script](https://github.com/lovesh/fork-off-substrate) to generate the new (PoS) genesis file and download old 
chain's state. Make sure the necessary files like metadata, binary, runtime wasm, types, etc are present and env variables are set before 
running the script  
8. Start nodes with the new genesis file.
9. Download the state of the new chain with script from step 4 and compare the JSON is same (there will be minor difference; in sudo account's nonce and in genesis accounts' locks)
10. Update code and docker images with new genesis and code.