## Collecting Kubernetes-Related Consul Service Mesh Envoy Dump Data
This guide explains how to collect Kubernetes-related Consul Service Mesh Envoy dump data using the provided shell script.

### Configurations and Environment Variables
Set the following environment variables before running the script:
- `SERVICE`: The name of the Consul service.
- `SERVICE_NS`: The Kubernetes namespace where the service resides.
- `CONTEXT`: The Kubernetes context to use.
- `OUT_DIR`: The output directory to save the collected data.

### Capture Options
The script supports the following `capture_options`:
- `--all`: Collects all available dump types, including logs, stats, and configuration.
- `--logs`: Captures Envoy logs.
- `--stats`: Collects Envoy statistics.
- `--clusters`: Fetches cluster-related data.
- `--config`: Collects the configuration dump.

### Kubernetes CLI Detection
Ensure the proper Kubernetes CLI is installed and configured:
- For `kubectl`: Verify it is installed and configured to access the cluster using `kubectl config get-contexts`.
- For `oc`: Ensure the `oc` CLI is set up for OpenShift clusters and properly authenticated.

#### Example: Check CLI Presence
```sh
# Validate that kubectl is working
kubectl version --client

# Validate that oc is working (if applicable)
oc version
```

### Example Commands
#### Collect All Dump Types
```sh
scripts/envoy-dumper.sh --all --service ${SERVICE} --namespace ${SERVICE_NS} --context ${CONTEXT} --output ${OUT_DIR}
```

#### Reset Outlier Detections
```sh
scripts/envoy-dumper.sh --clusters --reset-outliers --service ${SERVICE} --namespace ${SERVICE_NS} --context ${CONTEXT}
```

#### Example Envoy Capture (Successful script run)

```sh
=======================================================================================
                           Consul K8s | Envoy Sidecar Dumper
             Service: 'frontend' | Namespace: 'consul' | Cluster: 'k3d-c1'
=======================================================================================
17/02/2025-11:37:38 - [INFO] Detecting Kubernetes command-line tooling installed for cluster
17/02/2025-11:37:39 - [WARN] OpenShift-specific resources not detected. Assuming vanilla Kubernetes.
17/02/2025-11:37:39 - [INFO] Detecting Kubernetes command-line tooling installed for cluster
17/02/2025-11:37:39 - [WARN] OpenShift-specific resources not detected. Assuming vanilla Kubernetes.
17/02/2025-11:37:39 - [INFO] Setting Envoy log level to trace for service: frontend in namespace: consul
17/02/2025-11:37:39 - [INFO] Setting log level on pod/frontend-67f85b5478-f7sfs
17/02/2025-11:37:40 - [INFO] Successfully updated log level to trace on pod/frontend-67f85b5478-f7sfs
17/02/2025-11:37:40 - [INFO] Creating dump directories in envoy-dumper/
17/02/2025-11:37:40 - [INFO] Performing all dump actions.
17/02/2025-11:37:40 - [INFO] Fetching logs from pod/frontend-67f85b5478-f7sfs (container: consul-dataplane)
17/02/2025-11:37:40 - [INFO] Data saved to /Users/natemollica/envoy-parse/envoy-dumper/logs/k3d-c1/frontend-67f85b5478-f7sfs-logs.log
17/02/2025-11:37:40 - [INFO] Fetching config dump from pod/frontend-67f85b5478-f7sfs at 0:19000/config_dump?include_eds
17/02/2025-11:37:40 - [INFO] Data saved to /Users/natemollica/envoy-parse/envoy-dumper/config_dump/k3d-c1/frontend-67f85b5478-f7sfs-config_dump.json
17/02/2025-11:37:40 - [INFO] Fetching stats from pod/frontend-67f85b5478-f7sfs at 0:19000/stats?format=txt
17/02/2025-11:37:40 - [INFO] Data saved to /Users/natemollica/envoy-parse/envoy-dumper/stats/k3d-c1/frontend-67f85b5478-f7sfs-stats.txt
17/02/2025-11:37:41 - [INFO] Fetching clusters from pod/frontend-67f85b5478-f7sfs at 0:19000/clusters?format=txt
17/02/2025-11:37:41 - [INFO] Data saved to /Users/natemollica/envoy-parse/envoy-dumper/clusters/k3d-c1/frontend-67f85b5478-f7sfs-clusters.txt
17/02/2025-11:37:41 - [INFO] Fetching listeners from pod/frontend-67f85b5478-f7sfs at 0:19000/listeners?format=txt
17/02/2025-11:37:41 - [INFO] Data saved to /Users/natemollica/envoy-parse/envoy-dumper/listeners/k3d-c1/frontend-67f85b5478-f7sfs-listeners.txt
17/02/2025-11:37:41 - [INFO] All selected actions completed successfully!
```

### Troubleshooting and Notes
- **Environment Variables Not Found**: Ensure that all required environment variables (`SERVICE`, `SERVICE_NS`, `CONTEXT`) are set and exported correctly before running the script.
- **CLI Detection Fails**: Check if the correct CLI tool (e.g., `kubectl` or `oc`) is installed and accessible in your `$PATH`.
- **Permission Issues**: Ensure you have the necessary permissions to access the Kubernetes API and the Consul Service Mesh environment.
- **Output Directory Problems**: Verify the `OUT_DIR` path is writable and has adequate space for collected data.

Refer to the official documentation of Kubernetes, Consul, and Envoy Proxy for additional details on configuring and troubleshooting.