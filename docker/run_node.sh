#!/bin/bash

set -ueo pipefail

author_secret_seed=$1
author_aura_public=$2
author_grandpa_public=$3

callrpc() {
    curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d "$1"
}

wait_for_success() {
    if [ $# -eq 0 ]; then
        echo No command specified >&2
        return 1
    fi
    while ! ($@); do :; done
}

with_timeout() {
    local timeout="$1"
    shift
    
    sleep $timeout &
    local sproc=$!
	disown $sproc # keep the death of this command from being reported

    ($@) &
    local fproc=$!
    
    # wait for one of the processes to end
    while kill -0 $sproc 2>/dev/null && kill -0 $fproc 2>/dev/null; do :; done

    # end the sleep process if it is still running
    kill $sproc 2>/dev/null || true
	wait $sproc || true

    if kill $fproc 2>/dev/null; then
        echo Command "'"$@"'" timed out. >&2
        exit 124
    fi

    # success case, the command ran to completion, return it's status (could be nonzero)
    wait $fproc
}

quietly() {
    $@ >/dev/null 2>/dev/null
}

upload_keys() {
    # Wait for node to start
    with_timeout 15 wait_for_success quietly callrpc '[]'

    # The node has 1 authority. Create keys for it. The secret phrase, aura public key and grandpa
    # public key are passed as command line argument,
    local call='[
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "author_insertKey",
            "params": ["aura", "'$author_secret_seed'" , "'$author_aura_public'"]
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "author_insertKey",
            "params": ["gran", "'$author_secret_seed'", "'$author_grandpa_public'"]
        }
    ]'
	local result=$(callrpc "$call")
	jq . <<<$result
	jq -e '.[] | has("result")' >/dev/null <<<$result
}

# Run the node in background
./dock-testnet --dev --chain=remdev --rpc-external --ws-external --rpc-cors=all &
nodeproc=$!

upload_keys &
uploadproc=$!

wait $uploadproc
wait $nodeproc
