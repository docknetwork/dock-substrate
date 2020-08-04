#!/bin/bash

# The script will will exit if any command fails
set -ueo pipefail

DEFAULT_NODE_RPC_ENDPOINT='http://localhost:9933'

# If the node RPC endpoint is not provided, use the default one.
if [[ $# == 1 ]]
then
  node_rpc_url=$1
else
  node_rpc_url=$DEFAULT_NODE_RPC_ENDPOINT
fi

# Make the RPC call `author_rotateKeys` to the node using curl and get the response which will contain the session key.
# `-s` flag is silent mode, i.e. preventing the progress from being displayed.
rpc_resp=$(curl -s $node_rpc_url -H "Content-Type:application/json;charset=utf-8" -d '[{"jsonrpc":"2.0","id":1,"method":"author_rotateKeys","params":[]}]')

# Extract the hex formatted session key from the RPC call's response.
session_key_regex='(0x[A-Fa-f0-9]+)'
if [[ $rpc_resp =~ $session_key_regex ]]
then
  session_key=${BASH_REMATCH[1]}
else
  echo "Cannot get session key. Regex failed."
  exit 1
fi

# For colored output
GREEN_COLOR='\033[1;32m'
NOCOLOR='\033[0m'

echo -e "The session key is ${GREEN_COLOR}$session_key${NOCOLOR}"