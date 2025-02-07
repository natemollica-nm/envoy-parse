import os
import httpx
import json
import csv
import logging
from termcolor import colored

STATIC_CLUSTERS="static_clusters"
DYNAMIC_CLUSTERS="dynamic_active_clusters"
HEALTH_STATUS = {"HEALTHY": "✅ ", "UNHEALTHY": "❌ ", "UNKNOWN": "❔"}

# Configure logging
def setup_logging(log_level):
    """Set up logging for the script."""
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.debug("Logging setup complete.")

def fetch_envoy_data(admin_api, endpoints: list):
    envoy_responses = []

    for ep in endpoints:
        url = f"{admin_api}{ep}"
        try:
            response = httpx.get(url, timeout=5)
            response.raise_for_status()
            envoy_responses.append({"endpoint": ep, "data": response.json()})
        except httpx.HTTPError as err:
            logging.error(f"Failed to fetch {url}: {err}")
            return {"error": f"Request failed for {url}"}

    return envoy_responses


def parse_envoy_logs(files_or_dirs):
    """Parse files or directories containing Envoy logs and config dumps."""
    parsed_logs = []
    for path in files_or_dirs:
        if os.path.isdir(path):
            parsed_logs.extend(parse_directory(path))
        else:
            parsed_logs.extend(parse_file(path))
    return parsed_logs


def parse_directory(directory):
    """Parse all files in a directory recursively."""
    parsed_logs = []
    for root, _, files in os.walk(directory):
        for file in files:
            parsed_logs.extend(parse_file(os.path.join(root, file)))
    return parsed_logs


def parse_file(filepath):
    """Parse an individual file for Envoy logs or config dumps."""
    parsed_data = []
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            if filepath.endswith(".log"):
                parsed_data = parse_log_file(content)
            else:
                parsed_data = parse_json_file(content, filepath)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return parsed_data


def parse_log_file(content):
    """Parse content of a log file."""
    parsed_data = []
    for line in content.splitlines():
        try:
            parsed_data.append(json.loads(line))  # JSON log
        except json.JSONDecodeError:
            parsed_data.append({"raw": line.strip()})  # Fallback for plaintext logs
    return parsed_data


def parse_json_file(content, filepath):
    """Parse content of a JSON-compatible file."""
    try:
        return [json.loads(content)]
    except json.JSONDecodeError:
        print(f"Skipping non-JSON file: {filepath}")
    return []


def apply_filter(parsed_data, filter_func):
    """Apply a filter function to parsed Envoy data."""
    if not callable(filter_func):
        raise ValueError("Provided filter is not callable")
    return filter_func(parsed_data)


# Predefined filters
def filter_envoy_types(data):
    return [entry.get("@type", "unknown") for entry in data.get("configs", [])]


def filter_envoy_bootstrapped_clusters(data):
    return [
        entry.get("static_resources", {}).get("clusters", [])
        for entry in data.get("configs", [])
        if entry.get("bootstrap")
    ]


def filter_envoy_clusters(cluster_type):
    """Generalized filter for static or dynamic clusters."""

    def filter_func(data):
        if cluster_type == DYNAMIC_CLUSTERS:
            return [
                cluster
                for entry in data.get("configs", [])
                for cluster in entry.get(DYNAMIC_CLUSTERS, [])
            ]
        else:
            return [
                cluster
                for entry in data.get("configs", [])
                for cluster in entry.get(STATIC_CLUSTERS, {})
            ]

    return filter_func


def filter_envoy_endpoints(endpoint_type):
    """Generalized filter for static or dynamic endpoints."""

    def filter_func(data):
        return [
            endpoint
            for entry in data.get("configs", [])
            for endpoint in entry.get(endpoint_type, [])
        ]

    return filter_func


def filter_envoy_dynamic_endpoints_summary(data):
    """Summarize dynamic endpoints with cluster names and health statuses."""
    return [
        {
            "upstream_cluster": ep.get("endpoint_config", {}).get("cluster_name", "unknown"),
            "health_status": ep.get("endpoint_config", {}).get("endpoints", [{}])[0]
            .get("lb_endpoints", [{}])[0].get("health_status", "unknown"),
        }
        for entry in data.get("configs", []) if entry.get("dynamic_endpoint_configs")
        for ep in entry.get("dynamic_endpoint_configs", [])
    ]


def filter_envoy_relationships(data):
    """Extract relationships between listeners, filter chains, clusters, and endpoints."""
    if not isinstance(data, dict):
        logging.debug("Input data is not a dictionary.")
        return []

    # Extract relevant sections from config in a single pass
    static_clusters = []
    dynamic_clusters = []
    dynamic_endpoints = []
    dynamic_listeners = []

    for entry in data.get("configs", []): # /configs/0/bootstrap/static_resources
        static_clusters.extend(entry.get("static_resources", {}).get("clusters", []))
        dynamic_clusters.extend(entry.get("dynamic_active_clusters", []))
        dynamic_endpoints.extend(entry.get("dynamic_endpoint_configs", []))
        dynamic_listeners.extend(entry.get("dynamic_listeners", []))

    # Extract data using the pre-processed lists
    clusters = extract_clusters(static_clusters, dynamic_clusters)
    endpoints = extract_endpoints(dynamic_endpoints)
    listeners = extract_listeners(dynamic_listeners)

    logging.debug(f"Extracted clusters: {list(clusters.keys())}")
    logging.debug(f"Extracted endpoints: {endpoints}")
    logging.debug(f"Extracted listeners: {listeners}")

    # Build relationships in a single pass
    relationships = build_relationships(endpoints, clusters, listeners)

    return relationships


def extract_clusters(static_clusters, dynamic_clusters):
    """Extract both static and dynamic clusters from separate lists."""
    clusters = {}

    for cluster in static_clusters:
        cluster_name = cluster.get("name")
        if cluster_name:
            clusters[cluster_name] = cluster

    for dynamic_entry in dynamic_clusters:
        cluster = dynamic_entry.get("cluster", {})
        cluster_name = cluster.get("name")
        if cluster_name:
            clusters[cluster_name] = cluster

    logging.debug(f"Extracted clusters: {list(clusters.keys())}")
    return clusters


def extract_endpoints(dynamic_endpoints):
    """Extract dynamic endpoints and map them to their respective clusters."""
    endpoints = {}

    for ep in dynamic_endpoints:
        cluster_name = ep.get("endpoint_config", {}).get("cluster_name")
        if not cluster_name:
            continue

        lb_endpoints = [
            {
                "address": lb_ep.get("endpoint", {}).get("address", {}).get("socket_address", {}).get("address", "unknown"),
                "port": lb_ep.get("endpoint", {}).get("address", {}).get("socket_address", {}).get("port_value", "unknown"),
                "health_status": endpoint.get("lb_endpoints", [{}])[0].get("health_status", "UNKNOWN"),
            }
            for endpoint in ep.get("endpoint_config", {}).get("endpoints", [])
            for lb_ep in endpoint.get("lb_endpoints", [])
        ]

        endpoints[cluster_name] = lb_endpoints

    logging.debug(f"Extracted endpoints: {endpoints}")
    return endpoints


def extract_listeners(dynamic_listeners):
    """Extract all listeners along with their filter chains."""
    listeners = {}

    for listener in dynamic_listeners:
        listener_name = listener.get("name")
        filter_chains = listener.get("active_state", {}).get("listener", {}).get("filter_chains", [])
        listeners[listener_name] = filter_chains

    logging.debug(f"Extracted listeners: {listeners}")
    return listeners


def build_relationships(endpoints, clusters, listeners):
    """Build relationships between endpoints, clusters, and listeners."""
    relationships = []

    for cluster_name, cluster_endpoints in endpoints.items():
        matching_cluster = clusters.get(cluster_name)

        if not matching_cluster:
            logging.debug(f"Skipping cluster {cluster_name}: Not found in extracted clusters.")
            continue

        for listener_name, filter_chains in listeners.items():
            for chain in filter_chains:
                for filter_entry in chain.get("filters", []):
                    config = filter_entry.get("typed_config", {})

                    # Extract the cluster name from route config or direct cluster field
                    filter_cluster = config.get("cluster") or extract_cluster_from_route_config(config)
                    filter_name = filter_entry.get("name")

                    if filter_cluster and filter_cluster == cluster_name:
                        relationships.append({
                            "listener": listener_name,
                            "filter_chain": filter_name or filter_entry.get("name") or "unknown",
                            "cluster": cluster_name,
                            "endpoints": cluster_endpoints,
                        })

    logging.debug(f"Final relationships built: {relationships}")
    return relationships


def extract_cluster_from_route_config(config):
    """Extract cluster name from HTTP route configuration if present."""
    if "route_config" in config:
        for vh in config["route_config"].get("virtual_hosts", []):
            for route in vh.get("routes", []):
                if "route" in route and "cluster" in route["route"]:
                    return route["route"]["cluster"]
    return None

# Reusable function for UI & CLI
def parse_envoy_data(files_or_dirs, filter_type=None):
    """Parse Envoy logs/config files and apply filters."""
    parsed_logs = []
    for path in files_or_dirs:
        if os.path.isdir(path):
            parsed_logs.extend(parse_directory(path))
        else:
            parsed_logs.extend(parse_file(path))

    if filter_type and filter_type in FILTERS:
        filtered_data = [apply_filter(log, FILTERS[filter_type]) for log in parsed_logs if isinstance(log, dict)]
        return [item for sublist in filtered_data for item in sublist]

    return parsed_logs

# API-Compatible function
def analyze_envoy_data(data, filter_type=None):
    """Process raw JSON data from API request & apply filters."""
    if not isinstance(data, dict):
        return {"error": "Invalid JSON input"}

    if filter_type and filter_type in FILTERS:
        return FILTERS[filter_type](data)

    return data  # Return raw data if no filter is applied

# Function to process & return results
def process_envoy_request(data, filter_type):
    """API Hook: Process Envoy logs/configs based on filter_type."""
    logging.info(f"Processing request with filter: {filter_type}")
    return analyze_envoy_data(data, filter_type)


FILTERS = {
    "envoy_types": filter_envoy_types,
    "envoy_bootstrapped_clusters": filter_envoy_bootstrapped_clusters,
    "envoy_static_clusters": filter_envoy_clusters("static_clusters"),
    "envoy_dynamic_clusters": filter_envoy_clusters("dynamic_active_clusters"),
    "envoy_static_endpoints": filter_envoy_endpoints("static_endpoint_configs"),
    "envoy_dynamic_endpoints": filter_envoy_endpoints("dynamic_endpoint_configs"),
    "envoy_dynamic_endpoints_summary": filter_envoy_dynamic_endpoints_summary,
    "envoy_relationships": filter_envoy_relationships,
}

def write_csv(data, delimiter_type):
    """
    Write data to a CSV file.

    :param data: List of dictionaries representing the data rows.
    :param delimiter_type: Type of delimiter, e.g., "tab" or "csv".
    """
    file_name = "output.csv"  # File name defined inline
    try:
        delimiter = '\t' if delimiter_type == "tab" else ','  # Inline delimiter logic
        headers = data[0].keys() if data else []
        with open(file_name, "w", newline='') as csvfile:  # csvfile is now a TextIO
            writer = csv.DictWriter(csvfile, fieldnames=headers, delimiter=delimiter)
            writer.writeheader()
            writer.writerows(data)
        print(f"CSV output saved as '{file_name}'")
    except Exception as e:
        print(f"Error writing CSV to '{file_name}': {e}")

def format_columnized_output(data):
    """Format the output in a neatly aligned column format similar to `kubectl get pods`."""
    from tabulate import tabulate

    table_data = []
    headers = ["Listener", "Filter Chain", "Cluster", "Endpoints"]

    for entry in data:
        if isinstance(entry, dict):
            logging.debug(f"Processing table dictionary entry: {entry}")
            listener = entry.get("listener", "unknown")
            filter_chain = entry.get("filter_chain", "unknown")
            cluster = entry.get("cluster", "unknown")
            endpoints = ", ".join(
                f"{ep['address']}:{ep['port']} {HEALTH_STATUS.get(ep['health_status'])}" for ep in entry.get("endpoints", [])
            )

            table_data.append([listener, filter_chain, cluster, endpoints])

    return tabulate(table_data, headers=headers, tablefmt="grid")


def output_results(data, output_format, delimiter="csv"):
    """Output data in the specified format."""
    if output_format == "json":
        print(json.dumps(data, indent=2))
    elif output_format == "csv":
        write_csv(data, delimiter)
    else:
        print(format_columnized_output(data))

def main():
    import argparse
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Analyze Envoy Logs and Configs")
    parser.add_argument("--parse", nargs="+", help="Parse log files or directories")
    parser.add_argument("--filter", choices=FILTERS.keys(), help="Apply predefined filter")
    parser.add_argument("--output", choices=["json", "csv", "table"], default="json", help="Output format")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO",
                        help="Set the logging level")
    args = parser.parse_args()

    # Configure logging based on user-provided log level
    setup_logging(args.log_level)

    if args.parse:
        parsed_logs = parse_envoy_logs(args.parse)
        if args.filter:
            filtered_data = [apply_filter(log, FILTERS[args.filter]) for log in parsed_logs if isinstance(log, dict)]
            output_results([item for sublist in filtered_data for item in sublist], args.output)
        else:
            logging.warning("No filter specified. Outputting raw parsed data.")
            output_results(parsed_logs, args.output)


if __name__ == "__main__":
    main()
