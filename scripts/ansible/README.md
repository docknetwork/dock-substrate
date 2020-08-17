# Scripts

## Ansible playbook for testnode.

The playbook [poa-1-testnet-node](poa-1-testnet-node.yml) is used to run a testnet node, be it a validator, sentry
or a full node. The playbook has only been tested on remotes running Ubuntu 18.04 and RHEL 8.2 using ansible 2.9.6 with python 3.8. 
It requires python3 to be installed on the remote (where node will run) as well and sudo access to the remotes. It will setup Docker, 
pull the testnet node image, start a container running a node. These are the parameters

1. path to python interpreter on remote `ansible_python_interpreter`
1. node name as `node_name`
1. libp2p secret key as `libp2p_key`, if not provided, the node will generate a random key
1. whether to allow external RPC requests as `allow_ext_rpc`, defaults to false
1. whether the node is running as a validator or not as `is_validator`, defaults to false
1. if a node is a sentry of a validator as `sentry_of`, if not provided then ignored
1. whether will only connect to its reserved (whitelisted nodes) as `reserved_only`, defaults to false
1. its reserved nodes as an array `reserved_nodes`, defaults to empty array
1. if the node should use bootnodes or not as an array `bootnodes`, defaults to empty array
1. what telemetry url it should use as `telemetry_url`, default to no telemetry
1. if session key should be rotated, as `rotate_session_key`, defaults to false. If true, session key will be stored 
in a file called session_key.txt on the host.
1. pruning mode for the node, as `pruning`, this can be either `archive` or a positive integer.

The [sample hosts file](hosts.sample) can be checked for the parameters. Note that the sample file has several 
placeholders enclosed in angle brackets, i.e. like `<validator node ip>` or `<path of private key file>`, all of these 
should be appropriately filled or removed else the hosts file won't be parsable. The sample hosts file assumes password-less 
ssh access, but if you require an additional password, use the flag `-k` while running the playbook. If you are not using a 
private key but only a password, use `ansible_ssh_pass`

The sample file has a 3 tiered deployment where the 1st tier which is a validator only talks to its sentry. 
The sentry node is the second tier and talks to the validator its responsible for and other whitelisted 
(reserved) nodes which might be sentries of other validators or other validators or some other full nodes 
serving clients or bootnodes. The nodes serving clients or acting as full nodes are the 3rd tier.
The objective is to allow only whitelisted traffic (P2P or RPC) to tier 1 and 2 and only tier 3 allows client RPC traffic.  
A sentry most likely will have one full node dedicated to the serving RPC traffic from clients.  
The playbook uses the `host` variable to select the details of the node to run. In the sample hosts file, there are 3 hosts, 
`validator`, `sentry` and `fullnode`.

1. To run a validator, use
```
ansible-playbook -i <hosts file> poa-1-testnet-node.yml --extra-vars "host=validator rotate_session_key=true"
```
The `rotate_session_key=true` is only passed when session key needs to be rotated. This must be passed the first time node is being set.
The libp2p key, telemetry url, reserved nodes, etc can be provided in cli or through host file. They are shown in sample hosts file as an example.

2. To run a sentry, use
```
ansible-playbook -i <hosts file> poa-1-testnet-node.yml --extra-vars "host=sentry"
```
This will run a sentry node. The `sentry_of` argument is used to set the libp2p peer id of the validator this node is sentry for.
As above, the libp2p key, telemetry url, reserved nodes, etc can be provided in cli or through host file. They are shown in sample hosts file as an example.

3. To run a full node, use
```
ansible-playbook -i <hosts file> poa-1-testnet-node.yml --extra-vars "host=fullnode"
```
This will run a full node. 
As above, the libp2p key, telemetry url can be provided in cli or through host file. They are shown in sample hosts file as an example.
