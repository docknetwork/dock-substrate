## Substrate Dashboard

We are using a very slightly modified version of the Robonomics dashboard https://grafana.com/grafana/dashboards/13015 which has Substrate prometheus metrics aswell as node exporter metrics.

You can find our version in `./grafana-dashboard.json`

## Prometheus and Alert Manager config

Two files `prometheus.yaml` and `alerting-rules.yaml` are used for prometheus and alert manager config respectively. The simple configuration lets us scrape Substrate and Node Exporter metrics, giving us alerts through Alert Manager if theres node downtime. Please refer to the setup guide for more information.

## Setup guide

The good people at robonomics have created a nice guide to get you started: https://github.com/hubobubo/robonomics/wiki/Robonomics-(XRT)-metrics-using-Prometheus-and-Grafana - you can follow this and import the dashboard JSON here or their panel from Grafana.

## Healthcheck Lambda
There is an AWS Lambda running as a healthcheck for all PoS nodes (full and validator).
The code for it is in `./healthcheck-lambda.js`. 
