# Scripts

## Ansible playbook for testnode.

The playbook [poa-1-testnet-node](poa-1-testnet-node.yml) is used to run a testnet node, be it a validator, sentry
or a full node. The playbook has only been tested with Ubuntu and will setup Docker, pull the testnet node image, start a 
container and run a node. For non-Ubuntu machines, the playbook might be useful if Docker is already setup.
The playbook requires some variables which it either reads from the given host file or command line.
The [sample hosts file](hosts.sample) can be checked for the parameters. The sample file has a 3 tiered deployment where 
the 1st tier which is a validator only talks to its sentry. The sentry node is the second tier and talks to the validator 
its responsible for and other whitelisted (reserved) nodes which might be sentries of other validators or other validators 
or some other full nodes serving clients or bootnodes. The nodes serving clients or acting as full nodes are the 3rd tier.
The objective is to allow only whitelisted traffic (P2P or RPC) to tier 1 and 2 and only tier 3 allows client RPC traffic.  
A sentry most likely will have one full dedicated to the serving RPC traffic from clients.  
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