# EC2 Monitoring

## Disk Space Monitoring
Disk space can be monitored by installing the AWS CloudWatch Agent on the EC2 instance.

### Installation instructions:
* https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html
* Install collectd: `sudo apt-get install collectd`
* Setup the EC2 instance with an IAM Role that contains the `CloudWatchAgentServerPolicy`

An example of a CloudWatch Agent config file is included in this folder ![./cloudwatch-agent-config.json](cloudwatch-agent-config.json).
If using this file you will need to rename it to `config.json` and place it (on Linux) here: `/opt/aws/amazon-cloudwatch-agent/bin/config.json`.

Start: `sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json`
Stop: `sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a stop`

NOTE: if you change the config file you need to restart the agent

The configured metrics will then be shipped to CloudWatch where you can set up alarms, graphs, etc. based upon them.

### Notification to Slack Lambda
Using a CloudWatch Alarm and an SNS trigger that fires the Lambda with code from `cloudwatch-alert-lambda.js` a Slack alert can be sent whenever the alarm triggers.