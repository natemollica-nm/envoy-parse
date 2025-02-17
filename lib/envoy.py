import csv
import json
import logging
import os

import httpx
from tabulate import tabulate

STATIC_CLUSTERS = "static_clusters"
DYNAMIC_CLUSTERS = "dynamic_active_clusters"
HEALTH_STATUS = {"HEALTHY": "✅ ", "UNHEALTHY": "❌ ", "UNKNOWN": "❔"}


# Configure logging
def setup_logging(log_level):
    """
    Sets up application logging with a specified logging level.

    This function configures the logging library to use the given log level,
    ensures the format of log messages includes timestamp, log level, and the
    message itself, and specifies a date format. By default, if an invalid
    log level is provided, it falls back to "INFO".

    :param log_level: The log level to set for the logger. Must be one of the
        standard logging levels (e.g., "DEBUG", "INFO", "WARNING", "ERROR",
        "CRITICAL"), provided as a string.
    :type log_level: str
    :return: None
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), "INFO"),
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.debug("Logging setup complete.")


# Fetch data from envoy admin APIs
def fetch_envoy_data(admin_api, endpoints):
    """
    Fetches data from multiple endpoints using the given admin API and returns the
    responses in a structured format. The function validates input, sends HTTP
    requests to the specified endpoints, handles errors, and processes the responses.

    :param admin_api: Base URL of the admin API.
    :type admin_api: str
    :param endpoints: A list of endpoint paths to fetch data from.
    :type endpoints: list[str]
    :return: A list of dictionaries containing endpoint path and data, or an error
             dictionary if input validation fails.
    :rtype: list[dict] | dict
    """
    if not isinstance(endpoints, list):
        logging.error("Endpoints must be a list of strings.")
        return {"error": "Invalid endpoints input."}

    envoy_responses = []
    for ep in endpoints:
        url = f"{admin_api}{ep}"
        try:
            response = httpx.get(url, timeout=5)
            response.raise_for_status()
            envoy_responses.append({"endpoint": ep, "data": response.json()})
        except httpx.RequestError as err:
            logging.error(f"Request to {url} failed: {err}")
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON received from {url}")

    return envoy_responses


# File Parsing Utilities
def parse_envoy_logs(paths):
    """
    Parses Envoy access logs from given file paths or directories.

    This function takes a list of file paths or directories and attempts to parse
    the Envoy access logs contained within. For each valid directory, it processes
    the contained files. For each valid file, it parses the file. If the path does
    not point to a valid file or directory, a warning is logged.

    :param paths: A list of file and/or directory paths to be parsed.
    :type paths: list[str]
    :return: A list containing parsed data from the processed logs.
    :rtype: list
    """
    parsed_data = []
    for path in paths:
        if os.path.isdir(path):
            parsed_data.extend(parse_directory(path))
        elif os.path.isfile(path):
            parsed_data.extend(parse_file(path))
        else:
            logging.warning(f"Path {path} is not a valid file or directory.")
    return parsed_data


def parse_directory(directory):
    """
    Parses all log files within a specified directory and its subdirectories.

    This function traverses the given directory and its subdirectories recursively,
    identifying all files and processing them through the `parse_file` function.
    It then collects and aggregates the results into one comprehensive list of parsed
    logs. This is particularly useful for scenarios requiring batch processing or
    analysis of numerous log files located in various subdirectories.

    :param directory: The root directory to be traversed for log files.
    :type directory: str
    :return: A list containing parsed log entries aggregated from all processed files.
    :rtype: list
    """
    parsed_logs = []
    for root, _, files in os.walk(directory):
        for file in files:
            parsed_logs.extend(parse_file(os.path.join(root, file)))
    return parsed_logs


def parse_file(filepath):
    """
    Parses a file and detects the content type based on its extension or content.

    This function reads the specified file and attempts to parse its contents into
    a structured format. The parsing is performed based on the file extension, or
    if the extension is unknown or missing, by inspecting the content. Supported
    file types include `.log`, `.json`, `.txt`, and plain text files with no extension
    or unrecognized extensions.

    :param filepath: The path to the file to be parsed.
    :type filepath: str
    :return: A list containing parsed data from the file.
    :rtype: list
    :raises OSError: If there are issues with opening or reading the file.
    :raises Exception: If an unexpected error occurs during the parsing process.
    """
    parsed_data = []
    try:
        with open(filepath, "r") as f:
            content = f.read()
            # Try to detect file format if no extension or unknown extension
            if filepath.endswith(".log"):
                parsed_data = parse_log_file(content)
            elif filepath.endswith(".json"):
                parsed_data = parse_json_file(content, filepath)
            elif (
                filepath.endswith(".txt") or not os.path.splitext(filepath)[1]
            ):  # Default to txt if no extension
                parsed_data = parse_plain_text_file(content)
            else:
                # Detect content type if extension is non-standard or missing
                try:
                    # Attempt to parse as JSON
                    parsed_data = [json.loads(content)]
                except json.JSONDecodeError:
                    # Treat as plain text if JSON parsing fails
                    parsed_data = parse_plain_text_file(content)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return parsed_data


def parse_plain_text_file(content):
    """
    Parses plain text content into a list of dictionaries.

    This function takes a plain-text formatted input, splits it into
    lines, removes any leading and trailing whitespace, and excludes
    any empty or whitespace-only lines. Each line is then wrapped
    in a dictionary where the key is `"raw"` and the value is the
    cleaned content of that line.

    :param content: The content to be parsed, expected to be a plain
        text string.
    :type content: str
    :return: A list of dictionaries, with each dictionary containing
        a single key `"raw"`, mapping to cleaned lines of text.
    :rtype: list[dict]
    """
    return [{"raw": line.strip()} for line in content.splitlines() if line.strip()]


def parse_log_file(content):
    """
    Parses the content of a log file to extract structured data.

    The function processes each line of the input, attempting to decode it as a
    JSON object. If a line is not a valid JSON, it adds the line as raw plaintext
    to the resulting structured data. This allows the handling of mixed log formats
    containing both JSON and plaintext logs.

    :param content: The content of the log file to parse. The input is a multi-line
        string where each line represents a log entry.
    :type content: str
    :return: A list of structured data objects. Each object is either a parsed JSON
        dictionary or a dictionary with a "raw" key containing the original
        plaintext log line.
    :rtype: list[dict]
    """
    parsed_data = []
    for line in content.splitlines():
        try:
            parsed_data.append(json.loads(line))  # JSON log
        except json.JSONDecodeError:
            parsed_data.append({"raw": line.strip()})  # Fallback for plaintext logs
    return parsed_data


def parse_json_file(content, filepath):
    """
    Parse the given content as JSON data and return it as a list of JSON objects. If the content
    is not valid JSON, the function will catch the JSONDecodeError, log a message, and return
    an empty list. This is useful when reading multiple files and some may not contain valid
    JSON data.

    :param content: The content of the file expected to be in valid JSON format.
    :type content: str
    :param filepath: The path to the file being processed, used for logging non-JSON data.
    :type filepath: str
    :return: A list containing a single JSON object if content is successfully parsed,
        or an empty list in case of a JSONDecodeError.
    :rtype: list
    """
    try:
        return [json.loads(content)]
    except json.JSONDecodeError:
        print(f"Skipping non-JSON file: {filepath}")
    return []


# Filters for processing
def apply_filter(parsed_data, filter_func):
    """
    Applies a given filter function to the parsed data.

    This function takes parsed data and a filtering function, verifies that the
    filtering function is callable, and applies it to the parsed data. If the
    given filter function is not callable, the method logs an error and returns
    an empty list.

    :param parsed_data: The data to be filtered.
    :param filter_func: A callable function that applies a filter to the parsed
        data and returns the filtered result.
    :return: A list containing the filtered data. If the filter function is not
        callable, an empty list is returned.
    :rtype: list
    """
    if not callable(filter_func):
        logging.error("Provided filter_func is not callable.")
        return []
    return filter_func(parsed_data)


# Predefined filters
def filter_envoy_types(data):
    """
    Filters and retrieves the `@type` attribute from a list of configurations contained
    within the provided input. If a configuration entry does not contain the `@type`
    attribute, "unknown" is returned for that entry.

    :param data: A dictionary containing a key `configs` which holds a list of
        configuration entries. Each configuration entry is expected to be a dictionary
        with a possible `@type` key.
    :return: A list of strings representing the values of the `@type` attribute from
        each configuration entry, or "unknown" if the attribute is missing.
    :rtype: list[str]
    """
    return [entry.get("@type", "unknown") for entry in data.get("configs", [])]


def filter_envoy_bootstrapped_clusters(data):
    """
    Filters Envoy static_resources clusters from bootstrapped configurations.

    This function iterates through configuration entries provided in the input
    data and extracts static_resources clusters for entries marked as
    bootstrapped. It allows easy retrieval of relevant cluster configuration
    data.

    :param data: A dictionary containing configuration details. Expected to
        include a key "configs", which maps to a list of configuration
        entries with possible "bootstrap" markers and cluster details.
    :type data: dict

    :return: A list of clusters extracted from the static_resources section of
        the bootstrapped configuration entries.
    :rtype: list
    """
    return [
        entry.get("static_resources", {}).get("clusters", [])
        for entry in data.get("configs", [])
        if entry.get("bootstrap")
    ]


def filter_envoy_clusters(cluster_type):
    """
    Generates a function to filter Envoy clusters from data based on the
    specified cluster type.

    The returned function processes a data dictionary, filtering cluster
    information from the "configs" key. If the specified cluster type is
    DYNAMIC_CLUSTERS, it extracts dynamic cluster data; otherwise, it
    extracts static cluster data.

    :param cluster_type: The type of cluster to filter (e.g., DYNAMIC_CLUSTERS
                         or STATIC_CLUSTERS).
    :type cluster_type: str
    :return: A filtering function that extracts clusters based on the
             specified cluster type.
    :rtype: Callable[[dict], List[dict]]
    """

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
    """
    Creates a filtering function for extracting endpoints of a specific type from
    a dictionary structure typically representing envoy configurations.

    The returned function accepts a dictionary and applies the filtering logic
    to retrieve a flat list of all endpoints under the specified type by traversing
    the nested structure within the 'configs' key of the dictionary. The intention
    of the returned function is to streamline filtering operations based on
    dynamic endpoint types.

    :param endpoint_type: The type of endpoint to filter for. This is used as a lookup key
        within the nested dictionary structure to extract specific endpoints.
    :type endpoint_type: str

    :return: A function that takes a dictionary input and filters out a combined
        list of endpoints based on the provided `endpoint_type`.
    :rtype: Callable[[dict], list]
    """

    def filter_func(data):
        return [
            endpoint
            for entry in data.get("configs", [])
            for endpoint in entry.get(endpoint_type, [])
        ]

    return filter_func


def filter_envoy_dynamic_endpoints_summary(data):
    """
    Filters and processes dynamic endpoint configurations provided in the input data
    to extract cluster and health status information. The function iterates through
    the nested structure of dynamic endpoint configurations within the provided data
    and returns a summarized list of dictionaries containing `upstream_cluster` and
    `health_status` for each relevant endpoint. If certain keys are missing in the
    input, default values such as 'unknown' are used for the output.

    :param data: Dictionary containing hierarchical data structure of dynamic endpoint
        configurations. It must include `configs`, which is a list of entries holding
        `dynamic_endpoint_configs`. Each `dynamic_endpoint_config` contains the
        endpoint details to be filtered.
    :type data: dict
    :return: List of dictionaries summarizing the `upstream_cluster` and `health_status`
        extracted from the dynamic endpoint configurations. Every dictionary corresponds
        to a processed endpoint.
    :rtype: list
    """
    return [
        {
            "upstream_cluster": ep.get("endpoint_config", {}).get(
                "cluster_name", "unknown"
            ),
            "health_status": ep.get("endpoint_config", {})
            .get("endpoints", [{}])[0]
            .get("lb_endpoints", [{}])[0]
            .get("health_status", "unknown"),
        }
        for entry in data.get("configs", [])
        if entry.get("dynamic_endpoint_configs")
        for ep in entry.get("dynamic_endpoint_configs", [])
    ]


def filter_envoy_relationships(data):
    """
    Filters and extracts Envoy-related configuration relationships from the input
    data dictionary, processes clusters, endpoints, and listeners, and then builds
    relationships between them. This function operates by iterating through the
    input dictionary and aggregating all static and dynamic module information.

    :param data: A dictionary containing Envoy configuration data, typically with
                 sections such as `configs`, `static_resources`, and dynamic
                 cluster-related sections.
    :type data: dict

    :return: A list of extracted and constructed relationships between clusters,
             endpoints, and listeners based on the input configuration data.
    :rtype: list
    """
    if not isinstance(data, dict):
        logging.debug("Input data is not a dictionary.")
        return []

    # Extract relevant sections from config in a single pass
    static_clusters = []
    dynamic_clusters = []
    dynamic_endpoints = []
    dynamic_listeners = []

    for entry in data.get("configs", []):  # /configs/0/bootstrap/static_resources
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
    """
    Extracts and merges clusters from static and dynamic cluster data. The function
    iterates over both static and dynamic cluster lists, extracting clusters with
    a name and adding them to a dictionary. Static cluster names take precedence
    over dynamic ones if conflicts occur.

    :param static_clusters:
        List of static cluster dictionaries, expected to have at least a "name" field.
    :param dynamic_clusters:
        List of dynamic cluster dictionaries, where each is expected to have a
        "cluster" field containing a dictionary with at least a "name" field.
    :return:
        Dictionary where keys are cluster names and values are cluster information
        dictionaries.
    """
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
    """
    Extracts endpoint information for clusters from the provided dynamic endpoints.

    This function processes a list of dynamic endpoint configurations, extracts
    relevant information regarding cluster endpoints, and structures it into a
    flat dictionary format. Each cluster is mapped to a list of its respective
    load balancing endpoints, including their address, port, and health status.

    :param dynamic_endpoints: List of dictionaries, each representing dynamic
        endpoint configurations. Each dictionary may contain cluster and endpoint
        details.
    :type dynamic_endpoints: list[dict]
    :return: A dictionary where keys are cluster names and values are lists of
        dictionaries representing load balancing endpoints with their relevant
        details (address, port, and health status).
    :rtype: dict
    """
    endpoints = {}

    for ep in dynamic_endpoints:
        cluster_name = ep.get("endpoint_config", {}).get("cluster_name")
        if not cluster_name:
            continue

        lb_endpoints = [
            {
                "address": lb_ep.get("endpoint", {})
                .get("address", {})
                .get("socket_address", {})
                .get("address", "unknown"),
                "port": lb_ep.get("endpoint", {})
                .get("address", {})
                .get("socket_address", {})
                .get("port_value", "unknown"),
                "health_status": endpoint.get("lb_endpoints", [{}])[0].get(
                    "health_status", "UNKNOWN"
                ),
            }
            for endpoint in ep.get("endpoint_config", {}).get("endpoints", [])
            for lb_ep in endpoint.get("lb_endpoints", [])
        ]

        endpoints[cluster_name] = lb_endpoints

    logging.debug(f"Extracted endpoints: {endpoints}")
    return endpoints


def extract_listeners(dynamic_listeners):
    """
    Extracts and organizes the filter chains from a list of dynamic listeners, categorizing them by their
    respective listener names. This function processes a list of dynamic listeners, retrieves each listener's
    name and associated filter chains, and organizes them into a dictionary for further use.

    :param dynamic_listeners: A list of dictionaries representing dynamic listeners, where each dictionary
        contains details about a listener and can include its name and filter chains nested within additional
        levels of hierarchy.
    :type dynamic_listeners: list[dict]
    :return: A dictionary mapping listener names to their corresponding filter chains. Each key is a string
        representing a listener name, and the value is a list of filter chain details associated with
        that listener.
    :rtype: dict
    """
    listeners = {}

    for listener in dynamic_listeners:
        listener_name = listener.get("name")
        filter_chains = (
            listener.get("active_state", {})
            .get("listener", {})
            .get("filter_chains", [])
        )
        listeners[listener_name] = filter_chains

    logging.debug(f"Extracted listeners: {listeners}")
    return listeners


def build_relationships(endpoints, clusters, listeners):
    """
    Builds relationships between endpoints, clusters, and listeners.

    This function establishes a connection between predefined endpoints,
    clusters, and listeners. It relies on matching cluster names found in
    clusters and endpoints, and then associates these with the corresponding
    filters and filter chains within the listeners. A relationship is recorded
    if a filter's target cluster matches the cluster name from the input.

    :param endpoints: A mapping of cluster names to their respective endpoints.
    :type endpoints: dict
    :param clusters: A dictionary containing extracted cluster definitions,
        keyed by cluster names.
    :type clusters: dict
    :param listeners: A dictionary of listener configurations. Each listener name
        maps to its respective collection of filter chains.
    :type listeners: dict
    :return: A list of relationships mapping listeners, filter chains, clusters,
        and their associated endpoints.
    :rtype: list
    """
    relationships = []

    for cluster_name, cluster_endpoints in endpoints.items():
        matching_cluster = clusters.get(cluster_name)

        if not matching_cluster:
            logging.debug(
                f"Skipping cluster {cluster_name}: Not found in extracted clusters."
            )
            continue

        for listener_name, filter_chains in listeners.items():
            for chain in filter_chains:
                for filter_entry in chain.get("filters", []):
                    config = filter_entry.get("typed_config", {})

                    # Extract the cluster name from route config or direct cluster field
                    filter_cluster = config.get(
                        "cluster"
                    ) or extract_cluster_from_route_config(config)
                    filter_name = filter_entry.get("name")

                    if filter_cluster and filter_cluster == cluster_name:
                        relationships.append(
                            {
                                "listener": listener_name,
                                "filter_chain": filter_name
                                or filter_entry.get("name")
                                or "unknown",
                                "cluster": cluster_name,
                                "endpoints": cluster_endpoints,
                            }
                        )

    logging.debug(f"Final relationships built: {relationships}")
    return relationships


def extract_cluster_from_route_config(config):
    """
    Extracts the cluster name from a given route configuration.

    This function inspects a given configuration dictionary to retrieve the cluster
    name specified within the route definitions. If the configuration contains a
    "route_config" section, it iterates through the virtual hosts and their
    associated routes to locate and return the cluster name from the "route"
    information. If no cluster is found within the given configuration, the
    function returns None.

    :param config: The configuration dictionary containing potential "route_config"
        details with virtual hosts and routes.
    :type config: dict
    :return: The cluster name if found within the route configuration, or None if
        no cluster name exists.
    :rtype: str | None
    """
    if "route_config" in config:
        for vh in config["route_config"].get("virtual_hosts", []):
            for route in vh.get("routes", []):
                if "route" in route and "cluster" in route["route"]:
                    return route["route"]["cluster"]
    return None


# Reusable function for UI & CLI
def parse_envoy_data(files_or_dirs, filter_type=None):
    """
    Parses Envoy data from the provided file paths or directories and filters it
    optionally based on a given filter type. The function reads logs from files
    or directories and applies a filter if specified. The returned data consists
    of parsed or filtered Envoy logs.

    :param files_or_dirs: A list containing file or directory paths to process.
    :param filter_type: (Optional) A string denoting the type of filter to apply
        on the parsed logs. Must match one of the predefined filter types in
        FILTERS.
    :return: A list of parsed or filtered Envoy log entries.
    """
    parsed_logs = []
    for path in files_or_dirs:
        if os.path.isdir(path):
            parsed_logs.extend(parse_directory(path))
        else:
            parsed_logs.extend(parse_file(path))

    if filter_type and filter_type in FILTERS:
        filtered_data = [
            apply_filter(log, FILTERS[filter_type])
            for log in parsed_logs
            if isinstance(log, dict)
        ]
        return [item for sublist in filtered_data for item in sublist]

    return parsed_logs


# API-Compatible function
def analyze_envoy_data(data, filter_type=None):
    """
    Analyzes data from an Envoy system and applies a specified filter if provided. The function
    validates the input data to ensure it is a dictionary. If a ``filter_type`` is given and it
    is present in the predefined ``FILTERS`` dictionary, the corresponding filtering function
    is applied to the ``data``. If no filter is applied, the raw input data is returned. For
    invalid inputs, an error response will be returned.

    :param data: Input data to analyze. Must be a valid dictionary format.
    :type data: dict
    :param filter_type: Optional filter type to apply on the data. Must be a key present in
        the global ``FILTERS`` dictionary.
    :type filter_type: str or None
    :return: Filtered data if ``filter_type`` is valid or raw input data if no filter is
        applied. Returns an error response if the input is invalid.
    :rtype: dict
    """
    if not isinstance(data, dict):
        return {"error": "Invalid JSON input"}

    if filter_type and filter_type in FILTERS:
        return FILTERS[filter_type](data)

    return data  # Return raw data if no filter is applied


# Function to process & return results
def process_envoy_request(data, filter_type):
    """
    Processes data received from an Envoy request and applies a specified filter to analyze it.

    This function takes in Envoy request data and processes it by applying a filter
    as specified by the `filter_type` parameter. The filtered and analyzed data is
    then returned as the result.

    :param data: Represents the input data received from the Envoy request to be processed.
    :type data: Any
    :param filter_type: Specifies the type of filter to apply during data processing.
    :type filter_type: str
    :return: The result of analyzing the input data after applying the specified filter.
    :rtype: Any
    """
    logging.info(f"Processing request with filter: {filter_type}")
    return analyze_envoy_data(data, filter_type)


def write_csv(data, delimiter_type):
    """
    Writes a list of dictionaries to a CSV file using the specified delimiter type.

    This function takes a dataset represented as a list of dictionaries and writes
    it to a CSV file. The delimiter can be customized between a tab or a comma,
    based on the user specification.

    :param data: The list of dictionaries where each dictionary represents a
        row of the CSV data.
    :type data: list[dict]
    :param delimiter_type: The type of delimiter to use for separating columns in
        the CSV file. Possible values are "tab" for tab delimiter and any other
        value for comma delimiter.
    :type delimiter_type: str
    :return: None
    """
    file_name = "output.csv"  # File name defined inline
    try:
        delimiter = "\t" if delimiter_type == "tab" else ","  # Inline delimiter logic
        headers = data[0].keys() if data else []
        with open(file_name, "w", newline="") as csvfile:  # csvfile is now a TextIO
            writer = csv.DictWriter(csvfile, fieldnames=headers, delimiter=delimiter)
            writer.writeheader()
            writer.writerows(data)
        print(f"CSV output saved as '{file_name}'")
    except Exception as e:
        print(f"Error writing CSV to '{file_name}': {e}")


def format_columnized_output(data):
    """
    Formats the input data into a columnized table-like output using the `tabulate` library.

    The function processes a list of input dictionaries to extract specific information
    and arrange it into a visually structured format resembling a table. Each dictionary
    entry is expected to include keys such as `listener`, `filter_chain`, `cluster`, and
    `endpoints`. Missing keys will default to "unknown". The `endpoints` field is further
    processed to display detailed information based on an "address", "port", and "health_status".

    :param data: List of dictionaries where each dictionary represents a set of table data
                 with keys "listener", "filter_chain", "cluster", and "endpoints".
    :type data: list[dict]
    :return: A string representing the formatted table-like output.
    :rtype: str
    """
    table_data = []
    headers = ["Listener", "Filter Chain", "Cluster", "Endpoints"]

    for entry in data:
        if isinstance(entry, dict):
            logging.debug(f"Processing table dictionary entry: {entry}")
            listener = entry.get("listener", "unknown")
            filter_chain = entry.get("filter_chain", "unknown")
            cluster = entry.get("cluster", "unknown")
            endpoints = ", ".join(
                f"{ep['address']}:{ep['port']} {HEALTH_STATUS.get(ep['health_status'])}"
                for ep in entry.get("endpoints", [])
            )

            table_data.append([listener, filter_chain, cluster, endpoints])

    return tabulate(table_data, headers=headers, tablefmt="grid")


def output_results(data, output_format, delimiter="csv"):
    """
    Outputs data in the specified format.

    This function supports three output formats: JSON, CSV, and a default
    columnized format. Depending on the `output_format` specified, the
    appropriate formatting will be applied to `data` and displayed to the
    console or written using the relevant method. By default, the CSV output
    uses a comma as a delimiter unless otherwise specified via `delimiter`.

    :param data: The input data to be formatted and displayed. The structure
        and content of this data should align with the requirements of the
        selected `output_format`.
    :type data: Any
    :param output_format: Specifies the format in which the `data` will be
        output. Supported values are "json," "csv," or a default columnized
        display when no match is found.
    :type output_format: str
    :param delimiter: The delimiter to be used for separating values in CSV
        output. Defaults to a comma.
    :type delimiter: str, optional
    :return: This function does not return any value. The output is directly
        displayed or processed according to the specified format.
    :rtype: None
    """
    if output_format == "json":
        print(json.dumps(data, indent=2))
    elif output_format == "csv":
        write_csv(data, delimiter)
    else:
        print(format_columnized_output(data))


def main():
    """
    Main entry point for the script.

    This script provides functionality to analyze Envoy proxy logs and configs. It allows
    users to parse log files, apply specified filters, and output the results in various
    formats based on user-defined settings. Logging levels can be configured to control
    the verbosity of output messages.

    :raises SystemExit: If mandatory arguments are missing or invalid.
    :param list[str] --parse: List of log files or directories to parse.
    :param str --filter: A predefined log filter to apply.
    :param str --output: Desired output format for displaying the results. Defaults to "json".
    :param str --log-level: Logging level to set the verbosity. Defaults to "INFO".

    :return: None
    """
    import argparse

    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Analyze Envoy Logs and Configs")
    parser.add_argument("--parse", nargs="+", help="Parse log files or directories")
    parser.add_argument(
        "--filter", choices=FILTERS.keys(), help="Apply predefined filter"
    )
    parser.add_argument(
        "--output",
        choices=["json", "csv", "table"],
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set the logging level",
    )
    args = parser.parse_args()

    # Configure logging based on user-provided log level
    setup_logging(args.log_level)

    if args.parse:
        parsed_logs = parse_envoy_logs(args.parse)
        if args.filter:
            filtered_data = [
                apply_filter(log, FILTERS[args.filter])
                for log in parsed_logs
                if isinstance(log, dict)
            ]
            output_results(
                [item for sublist in filtered_data for item in sublist], args.output
            )
        else:
            logging.warning("No filter specified. Outputting raw parsed data.")
            output_results(parsed_logs, args.output)


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

if __name__ == "__main__":
    main()
