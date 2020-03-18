#!/bin/bash

# Run the node in background
./dock-testnet --dev --chain=remdev --rpc-external --ws-external --rpc-cors=all &

# Sleep to ensure node has started. This is a temporary hack. The right solution would be to check node status in a loop
sleep 15

# The node has 1 authority. Create keys for it. The secret phrase, aura public key and grandpa public key are passed as command line argument,
curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d '{"jsonrpc":"2.0","id":1,"method":"author_insertKey","params": ["aura","'"$1"'","'"$2"'"]}'
curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d '{"jsonrpc":"2.0","id":1,"method":"author_insertKey","params": ["gran","'"$1"'","'"$3"'"]}'

# Making script run forever
sleep infinity