# Scripts

## Ansible playbook to run AWS ec2 instance with a dock-node.

This script will create a keypair and security groups, launch an EC2 instance with a dock-node and configure alerts.

Variables:

1. `aws_profile` - AWS profile to be used
2. `aws_region` - AWS region to be used
3. `instance_host` - host vars to be used to launch the dock-node
4. `ssh_key_name` - ssh public key name to be used
5. `ssh_key_pub` - file path of the ssh public key to be used
6. `alarm_lambda_arn` - arn of the lambda function to be invoked in case of alarm
7. `name` to use for the created instance and node naming
8. `instance_type` - the type of the EC2 instance to be used, default to `t3.large`
9. `instance_role` - role assigned to the EC2 instance, default to `CloudWatchAgent_Role`
10. `ami_name` - AMI name to launch an instance from, default to `ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20230601`
11. `volume_size` - volume size to be created in GB. The default is `300`
12. `persistent` - don't delete a volume on termination. Default to `false`
13. `snapshot_id` - optional snapshot id to be used to instantiate the volume from

`instance_host` will represent an EC2 instance with dynamic IP.

Variables ([`instance_host`:vars]):

1. path to python interpreter on remote `ansible_python_interpreter`
2. node name as `node_name`
3. libp2p secret key as `libp2p_key`, if not provided, the node will generate a random key
4. whether to allow external RPC requests as `allow_ext_rpc`, defaults to false
5. whether to allow external Prometheus interfaces as `allow_ext_prom`, defaults to false
6. whether the node is running as a validator or not as `is_validator`, defaults to false
7. if a node is a sentry of a validator as `sentry_of`, if not provided then ignored
8. whether will only connect to its reserved (whitelisted nodes) as `reserved_only`, defaults to false
9. its reserved nodes as an array `reserved_nodes`, defaults to empty array
10. if the node should use bootnodes or not as an array `bootnodes`, defaults to empty array
11. what telemetry url it should use as `telemetry_url`, default to no telemetry
12. if session key should be rotated, as `rotate_session_key`, defaults to false. If true, session key will be stored
in a file called session_key.txt on the host.
13. pruning mode for the node, as `pruning`, this can be either `archive` or a positive integer.
14. chain spec file name present in `cspec` directory of this repo's root as `chain_spec_file`
15. tag of the docker image to download as `docker_image_tag`
16. `export_aws_metrics` if there's a need to install `amazon-cloudwatch-agent`
17. `overriden_host` to override `host` from the context
18. `chains_data_path` specifies a directory containing chains data to be copied if needed
19. `copy_chains_data` to copy chains data to the created docker volume. Default to `false`

Run a node:

```
ansible-playbook -i <hosts file> ec2-run-node.yml --extra-vars "host=Mainnet"
```

## Ansible playbook to stop AWS ec2 instance with a dock-node.

Variables:
1. `aws_profile` - AWS profile to be used
2. `aws_region` - AWS region to be used
3. `alarm_lambda_arn` - arn of the lambda function to be invoked in case of alarm
4. `name` to use for the created instance and node naming
5. `ami_name` - AMI name to launch an instance from, default to `ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20230601`
6. `terminate` - terminate instance instead of stopping, default to `false`

Stop a node:

```
ansible-playbook -i <hosts file> ec2-stop-node.yml --extra-vars "host=Mainnet"
```

Terminate a node:

```
ansible-playbook -i <hosts file> ec2-stop-node.yml --extra-vars "host=Mainnet" --extract-vars="terminate=true"
```

## Ansible playbook to enable SSH access to the AWS ec2 instance with a dock-node.

Variables:
1. `aws_profile` - AWS profile to be used
2. `aws_region` - AWS region to be used
3. `name` to use for the instance

Open SSH port:

```
ansible-playbook -i <hosts file> ec2-enable-ssh.yml --extra-vars "host=Mainnet"
```

## Ansible playbook to disable SSH access to the AWS ec2 instance with a dock-node.

Variables:
1. `aws_profile` - AWS profile to be used
2. `aws_region` - AWS region to be used
3. `name` to use for the instance

Close SSH port:

```
ansible-playbook -i <hosts file> ec2-disable-ssh.yml --extra-vars "host=Mainnet"
```

## Ansible playbook to extend the disk size for an AWS ec2 instance with a dock-node.

This script will modify the AWS volume, and connect to the EC2 instance to extend the partition and the file system using SSH.

Variables:
1. `aws_profile` - AWS profile to be used
2. `aws_region` - AWS region to be used
3. `name` - to use for the instance
4. `volume_size` - new size to be set for the volume

Resize the volume:

```
ansible-playbook -i <hosts file> ec2-set-volume-size.yml --extra-vars "host=Mainnet"
```

## Ansible playbook to set new volume size for an AWS ec2 instance

This script will modify the AWS volume, but does NOT connect to the EC2 instance to extend the partition and the file system

Variables:
1. `aws_access_key_id` - AWS access key to be used
2. `aws_secret_key` - AWS secret to be used
2. `aws_region` - AWS region where the EC2 instance is running
3. `instance_id` - the AWS instance id for the EC2 instance to be modified
4. `volume_size` - new size to be set for the volume

Resize the volume:

```
ansible-playbook -i <hosts file> ec2-set-volume-size.yml --extra-vars "aws_region=${{aws_region}} instance_id=${{instance_id}} aws_secret_key=$AWS_SECRET_KEY aws_access_key_id=$AWS_ACCESS_KEY_ID volume_size=${{disk_size}}"
```

## Ansible playbook to setup a gateway from the AWS ec2 instance with a dock-node.

Requires `geerlingguy.certbot` role installed.

Variables:

1. `aws_profile` - AWS profile to be used
2. `aws_region` - AWS region to be used
3. `name` - to use for the instance
4. `restricted_cidr_ip` - set of IP addresses to allow `https` connections from. If provided, only port `443` will be open for the supplied IP mask.

Variables ([`instance_host`:vars]):

1. path to python interpreter on remote `ansible_python_interpreter`
2. `domain` to issue certs for
3. `admin_email` to be included in certificates
4. `nginx_dir` to take the nginx base configuration from