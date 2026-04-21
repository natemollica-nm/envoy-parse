# Envoy Parse

A CLI tool for parsing and analyzing Envoy proxy config dumps. Built for SREs and infrastructure engineers troubleshooting service mesh issues across Consul, Istio, NGINX, and other Envoy-based architectures.

## What It Does

- Parses Envoy `/config_dump` JSON output (with or without `?include_eds`)
- Extracts and maps relationships between listeners, filter chains, clusters, and endpoints
- Handles SNI-based dynamic routing (terminating gateways, mesh gateways)
- Supports JSON, text, and log file formats
- Outputs results as JSON, CSV, or formatted tables

## Installation

```sh
git clone <repo-url>
cd envoy-parse
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```sh
python envoy.py --parse <file-or-directory> [--filter <filter>] [--output json|csv|table] [--log-level DEBUG|INFO|WARNING|ERROR]
```

### CLI Arguments

| Argument      | Description                                                     |
|---------------|-----------------------------------------------------------------|
| `--parse`     | One or more config dump files or directories to parse.          |
| `--filter`    | Apply a predefined filter (see table below).                    |
| `--output`    | Output format: `json` (default), `csv`, or `table`.            |
| `--log-level` | Logging verbosity: `DEBUG`, `INFO` (default), `WARNING`, `ERROR`. |

### Available Filters

| Filter                            | Description                                                        |
|-----------------------------------|--------------------------------------------------------------------|
| `envoy_types`                     | List `@type` values from each config section.                      |
| `envoy_bootstrapped_clusters`     | Extract clusters from the bootstrap `static_resources`.            |
| `envoy_static_clusters`           | List all static clusters from `ClustersConfigDump`.                |
| `envoy_dynamic_clusters`          | List all dynamic (xDS-delivered) clusters.                         |
| `envoy_static_endpoints`          | List static endpoint configurations.                               |
| `envoy_dynamic_endpoints`         | List dynamic endpoint configurations (requires `?include_eds`).    |
| `envoy_dynamic_endpoints_summary` | Summarize dynamic endpoints with cluster name and health status.   |
| `envoy_relationships`             | Map listeners → filter chains → clusters → endpoints.             |

## Collecting Config Dumps

Capture the Envoy admin config dump from your proxy. The method depends on your environment.

### Consul Dataplane (ECS)

```sh
# Without EDS (cluster/listener relationships only)
aws ecs execute-command --cluster <cluster> --task <task-id> \
  --container consul-dataplane \
  --command "wget -qO- http://127.0.0.1:19000/config_dump" \
  --interactive > config_dump.json

# With EDS (includes endpoint addresses and health status)
aws ecs execute-command --cluster <cluster> --task <task-id> \
  --container consul-dataplane \
  --command "wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds'" \
  --interactive > config_dump_eds.json
```

### Consul on Kubernetes

```sh
# Sidecar proxy
kubectl exec <pod> -c envoy-sidecar -- \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > config_dump.json

# Mesh gateway
kubectl exec <mesh-gw-pod> -c mesh-gateway -- \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > mesh_gw_dump.json

# Terminating gateway
kubectl exec <tgw-pod> -c terminating-gateway -- \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > tgw_dump.json

# Ingress gateway
kubectl exec <igw-pod> -c ingress-gateway -- \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > igw_dump.json
```

### Istio / Generic Envoy Sidecar

```sh
kubectl exec <pod> -c istio-proxy -- \
  curl -s 'http://127.0.0.1:15000/config_dump?include_eds' > config_dump.json
```

### Consul on Nomad

```sh
# Sidecar proxy — exec into the sidecar task within the allocation
nomad alloc exec -task connect-proxy-<service> <alloc-id> \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > config_dump.json

# Mesh gateway
nomad alloc exec -task mesh-gateway <alloc-id> \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > mesh_gw_dump.json

# Terminating gateway
nomad alloc exec -task terminating-gateway <alloc-id> \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > tgw_dump.json

# Ingress gateway
nomad alloc exec -task ingress-gateway <alloc-id> \
  wget -qO- 'http://127.0.0.1:19000/config_dump?include_eds' > igw_dump.json
```

### NGINX + Envoy Sidecar

```sh
# The Envoy sidecar admin port may vary; 19000 is common
kubectl exec <pod> -c envoy-sidecar -- \
  curl -s 'http://127.0.0.1:19000/config_dump?include_eds' > config_dump.json
```

> **Tip:** Always use `?include_eds` when possible. Without it, endpoint data is unavailable and the tool will display `N/A (no EDS)` in the Endpoints column.

> **Note:** When capturing via `aws ecs execute-command`, the session exit message may be appended to the output file. Clean the trailing non-JSON content before parsing, or the file will be skipped.

## Troubleshooting Examples

### Sidecar Proxy — Verify upstream routing

Check which clusters a sidecar's listeners route to and whether endpoints are healthy:

```sh
python envoy.py --parse sidecar_dump.json --filter envoy_relationships --output table
```

```
+---------------------+-----------------------------------+----------------------------------------------+-----------------------------------+
| Listener            | Filter Chain                      | Cluster                                      | Endpoints                         |
+=====================+===================================+==============================================+===================================+
| public_listener:443 | envoy.filters.network.http_conn.. | backend-api.default.dc1.internal.consul      | 10.0.1.50:8080 ✅                 |
+---------------------+-----------------------------------+----------------------------------------------+-----------------------------------+
```

### Mesh Gateway — Map peering and cross-DC routes

Mesh gateways use SNI-based routing. The tool detects this automatically and maps all reachable clusters:

```sh
python envoy.py --parse mesh_gw_dump.json --filter envoy_relationships --output table
```

```
+-------------------------+----------------------------------------------------------------------+------------------------------------------+--------------+
| Listener                | Filter Chain                                                         | Cluster                                  | Endpoints    |
+=========================+======================================================================+==========================================+==============+
| default:10.1.7.110:8443 | envoy.filters.network.tcp_proxy                                      | exported~vault.default.us-east-1.consul  | N/A (no EDS) |
+-------------------------+----------------------------------------------------------------------+------------------------------------------+--------------+
| default:10.1.7.110:8443 | envoy.filters.network.sni_cluster -> envoy.filters.network.tcp_proxy | vault.default.us-east-1.consul           | N/A (no EDS) |
+-------------------------+----------------------------------------------------------------------+------------------------------------------+--------------+
```

### Terminating Gateway — Verify external service routing

Terminating gateways also use SNI-based routing to reach external services registered in the mesh:

```sh
python envoy.py --parse tgw_dump.json --filter envoy_relationships --output table
```

### Ingress Gateway — Check inbound listener configuration

```sh
python envoy.py --parse igw_dump.json --filter envoy_relationships --output table
```

### Inspect cluster details

```sh
# List all dynamic clusters
python envoy.py --parse config_dump.json --filter envoy_dynamic_clusters --output json

# List all static (bootstrap) clusters
python envoy.py --parse config_dump.json --filter envoy_static_clusters --output json

# Endpoint health summary (requires ?include_eds)
python envoy.py --parse config_dump_eds.json --filter envoy_dynamic_endpoints_summary --output table
```

### Batch parse a directory of dumps

```sh
python envoy.py --parse ./dumps/ --filter envoy_relationships --output table
```

### Debug with verbose logging

```sh
python envoy.py --parse config_dump.json --filter envoy_relationships --output table --log-level DEBUG
```

## Development

### Running Tests

```sh
pytest tests/
```

### Linting and Formatting

```sh
flake8 envoy.py
black .
isort .
```

## Contributing

- Branch from `main` using `feature/<name>` branches.
- Ensure all tests pass and code is formatted before submitting a PR.
- Add tests for new filters or parsing logic.

## License

MIT License.
