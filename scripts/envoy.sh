#!/usr/bin/env sh

# Constants
OPENSHIFT_CLI=oc
KUBERNETES_CLI=kubectl
IS_OPENSHIFT=0
COMPRESS=0 # Default: do not compress
DEFAULT_CONTEXT="dc1"
DEFAULT_OUTPUT_DIR="envoy-dumper"
DEFAULT_FORMAT="txt"
DEFAULT_LOG_LEVEL="trace"
DUMP_TYPES="clusters config_dump listeners logs stats tcpdump"

# Directory management actions
ACTION_CLEAR="clear"
ACTION_CREATE="create"

# Colors
COLOR_INFO="\e[1;36m"
COLOR_BLUE="\e[1;34m"
COLOR_WARN="\033[1;33m"
COLOR_ERROR="\033[1;31m"
COLOR_RESET="\033[0m"
COLOR_DIM="\033[2m"
##################
INTENSE_BLUE="\033[1;94m"
INTENSE_CYAN="\033[1;96m"

# Error messages
ERR_MISSING_SERVICE="Service name is required. Use '--service' or '-s' to specify it."
ERR_MISSING_NAMESPACE="Namespace is required. Use '--namespace' or '-n' to specify it."
ERR_FAILED_DIR_CREATION="Failed to create directory: %s"
ERR_CLI_NOT_FOUND="Neither 'oc' nor 'kubectl' is available. Please install one of them to proceed."
ERR_NO_PODS_FOUND="No pods found for service: %s in namespace: %s"

# Default configuration and environment variables
export CONTEXT="$DEFAULT_CONTEXT"       # Default Kubernetes context
export SERVICE=""                       # Kubernetes service name
export SERVICE_NS=""                    # Kubernetes service namespace
export OUTPUT_DIR="$DEFAULT_OUTPUT_DIR" # Default directory for output
export CLEAR_DUMP_DIR=0                 # Flag for clearing the output directory
export ALL=1                            # Flag to indicate dump of all resources
export LOGS=0                           # Collect Envoy logs
export STATS=0                          # Collect Envoy stats
export CONFIG=0                         # Collect Envoy configuration
export CLUSTERS=0                       # Collect Envoy cluster details
export LISTENERS=0                      # Collect Envoy listener details
export RESET_COUNTERS=0                 # Reset Envoy outlier detection counters
export FORMAT="$DEFAULT_FORMAT"         # Default output format
export LOG_LEVEL="$DEFAULT_LOG_LEVEL"   # Default Envoy log level
export KUBE_CLI=                        # Kubernetes CLI (kubectl or "${KUBE_CLI}")

# Function to display a banner
banner() {
  printf '%s\n' "################################################"
  printf '%b%s%b\n' "${COLOR_BLUE}Consul K8s | Envoy Sidecar Dumper${COLOR_RESET}"
  printf "Service: '%s' | Namespace: '%s' | Cluster: '%s'\n" "$SERVICE" "$SERVICE_NS" "$CONTEXT"
  printf '%s\n\n' "################################################"
}

# Function to display usage information
usage() {
  banner
  cat <<EOF

Usage: $(basename "$0") [parameters] [capture_options] [options]

Parameters (Required):
  --context              Kubernetes context (e.g., dc1, dc2)
  -s, --service          Kubernetes service deployment name
  -n, --namespace        Kubernetes service namespace
Capture Options:
  -a, --all              Dump Envoy logs, configuration, clusters, and listeners
  --logs                 Collect Envoy logs at the specified log level (--log-level)
  --stats                Collect Envoy stats
  --config               Collect Envoy configuration
  --clusters             Collect Envoy cluster details
  --listeners            Collect Envoy listener details
Options:
  --help                 Show this help menu
  --format               Output dump format (text/json; default: $FORMAT)
  --out-dir              Directory for output files (default: $OUTPUT_DIR)
  --log-level            Set Envoy logging level (default: $LOG_LEVEL)
  -r, --reset-counters   Reset Envoy counters
  -rd, --reset-dump-dir  Clear the output dump directory
EOF
  exit "${1:-0}"
}

# Define the function to handle print messages with advanced formatting
highlight_message() {
  text="$1"    # The input text to process
  pattern="$2" # The pattern to highlight
  color="$3"   # ANSI color code for highlighting

  # Use `printf` to pass actual escape sequences into sed
  echo "$text" | sed -E "s|(${pattern})|$(printf '%b' "${color}")\1$(printf '\033[0m')|g"
}

# Log function with levels
logger() {
  level="$1"
  shift
  now=$(date '+%d/%m/%Y-%H:%M:%S')

  # Highlights for specific patterns
  message="$*"
  # Highlight specific patterns
  message=$(highlight_message "$message" "pod/[a-zA-Z0-9_-]+" "${INTENSE_BLUE}")
  message=$(highlight_message "$message" "0:19000/[a-zA-Z0-9_./?=-]+" "${LIGHT_CYAN}")
  message=$(highlight_message "$message" "\/[a-zA-Z0-9_./-]+" "${INTENSE_CYAN}")

  # Print the formatted message
  case "$level" in
  INFO)
    printf "%s - %b%s%b\n" "$now"  "${COLOR_INFO}[INFO]${COLOR_RESET} " "$message" "${COLOR_RESET}"
    ;;
  WARN)
    printf "%s - %b%s%b\n" "$now"  "${COLOR_WARN}[WARN]${COLOR_RESET} " "$message" "${COLOR_RESET}"
    ;;
  ERROR)
    printf "%s - %b%s%b\n" "$now" "${COLOR_ERROR}[ERROR]${COLOR_RESET} " "$message" "${COLOR_RESET}"
    ;;
  *)
    printf "%s - %b%s%b\n" "$now"   "${COLOR_BLUE}[LOG]${COLOR_RESET} " "$message" "${COLOR_RESET}"
    ;;
  esac
}

# Function to handle errors (standardized)
err() {
  message="$1"
  exit_code="${2:-1}"
  logger ERROR "$message" >&2
  exit "$exit_code"
}

verify_installed() {
  tool="$1"
  command -v "${tool}" >/dev/null 2>&1
}

# Function to verify and set KUBE_CLI
set_kube_cli() {
  cli_tool=$1
  KUBE_CLI="$(which "${cli_tool}")"
}

# Function to check OpenShift-specific resources
detect_openshift_resources() {
  if ${KUBE_CLI} api-resources | grep -q "project.openshift.io"; then
    logger INFO "OpenShift-specific resources detected. Cluster is OpenShift."
    export IS_OPENSHIFT=1
  else
    logger WARN "OpenShift-specific resources not detected. Assuming vanilla Kubernetes."
    export IS_OPENSHIFT=0
  fi
}

# Main function to detect Kubernetes CLI
detect_kube_cli() {
  logger INFO "Detecting Kubernetes command-line tooling installed for cluster"

  # Check for OpenShift CLI (`oc`)
  if verify_installed ${OPENSHIFT_CLI}; then
    set_kube_cli ${OPENSHIFT_CLI}
    detect_openshift_resources

    # Fallback to Kubernetes CLI (`kubectl`) if not OpenShift
    if [ "${IS_OPENSHIFT}" -eq 0 ] && verify_installed ${KUBERNETES_CLI}; then
      set_kube_cli ${KUBERNETES_CLI}
    elif [ "${IS_OPENSHIFT}" -eq 0 ]; then
      err "$ERR_CLI_NOT_FOUND"
    fi
    return 0
  fi

  # Check for Kubernetes CLI (`kubectl`) if OpenShift CLI is not installed
  if verify_installed ${KUBERNETES_CLI}; then
    set_kube_cli ${KUBERNETES_CLI}
    export IS_OPENSHIFT=0
    return 0
  fi

  # Error if no CLI is available
  err "$ERR_CLI_NOT_FOUND"
}

is_compress_only_run() {
  [ "$COMPRESS" -eq 1 ] && [ "$LOGS" -eq 0 ] && [ "$STATS" -eq 0 ] && [ "$CONFIG" -eq 0 ] && [ "$CLUSTERS" -eq 0 ] && [ "$LISTENERS" -eq 0 ] && [ "$ALL" -ne 1 ]
}

# Ensure required variables are set
validate_inputs() {
  # If --compress is the only action, skip the validation for service and namespace
  if is_compress_only_run; then
    logger INFO "Running in --compress-only mode. Skipping service and namespace validation."
    return 0
  fi

  # Proceed with normal validation for capture actions
  detect_kube_cli
  [ -z "$KUBE_CLI" ] && err "$ERR_CLI_NOT_FOUND"
  [ -z "$SERVICE" ] && err "$ERR_MISSING_SERVICE"
  [ -z "$SERVICE_NS" ] && err "$ERR_MISSING_NAMESPACE"
}

get_pods() {
  service_ns="$1"
  service_name="$2"
  pods

  pods=$("${KUBE_CLI}" get pods --namespace "$service_ns" --context "$CONTEXT" --selector="app=$service_name" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  if [ -z "$pods" ]; then
    err "$(printf "${ERR_NO_PODS_FOUND}" "$service_name" "$service_ns")"
  fi
  echo "$pods"
}

manage_dump_directory() {
  action="$1"
  case "$action" in
  "$ACTION_CLEAR")
    logger INFO "Clearing contents of dump directories in $OUTPUT_DIR/"
    for dump in $DUMP_TYPES; do
      path="$OUTPUT_DIR/$dump"
      if [ -d "$path" ]; then
        rm -rf "${path:?}"/* || err "Failed to clear the directory: $path"
        logger INFO "Cleared directory: $path"
      fi
    done
    ;;
  "$ACTION_CREATE")
    logger INFO "Creating dump directories in $OUTPUT_DIR/"
    mkdir -p "$OUTPUT_DIR" || err "$(printf "$ERR_FAILED_DIR_CREATION" "$OUTPUT_DIR")"
    for dump in $DUMP_TYPES; do
      path="$OUTPUT_DIR/$dump/$CONTEXT"
      mkdir -p "$path" || err "$(printf "$ERR_FAILED_DIR_CREATION" "$path")"
    done
    ;;
  *)
    err "Invalid action for manage_dump_directory: $action"
    ;;
  esac
}

reset_outlier_detection() {
  namespace="$1"
  service="$2"
  context="$3"

  logger INFO "Resetting outlier detection counters for $namespace/$service sidecar proxy"

  # Fetch pods
  pod_list=$("${KUBE_CLI}" get pods --namespace "$namespace" --context "$context" --selector="app=$service" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  if [ -z "$pod_list" ]; then
    logger WARN "No pods found for service $service in namespace $namespace"
    return 1 # Return failure if no pods are found
  fi

  # Reset counters for each pod
  for pod in $pod_list; do
    logger INFO "Resetting counters for pod $pod"
    "${KUBE_CLI}" exec --namespace "$namespace" --context "$context" "pod/$pod" -c "${service#consul-}" -- \
      curl -s -XPOST "$ADMIN_API/$OUTLIER_COUNTER_RESET_ENDPOINT" >/dev/null 2>&1 || {
      logger ERROR "Failed to reset counters on pod $pod"
      return 1
    }
    logger INFO "Successfully reset counters on pod $pod"
  done

  return 0
}

# Example: set_log_level function with consistent error handling
set_log_level() {
  validate_inputs
  logger INFO "Setting Envoy log level to $LOG_LEVEL for service: $SERVICE in namespace: $SERVICE_NS"

  # Fetch pod list
  pod_list=$("${KUBE_CLI}" get pods --namespace "$SERVICE_NS" --context "$CONTEXT" --selector="app=$SERVICE" -o jsonpath='{.items[*].metadata.name}')
  if [ -z "$pod_list" ]; then
    logger ERROR "No pods found for service: $SERVICE in namespace: $SERVICE_NS"
    return 1 # Return failure so the main logic can handle it
  fi

  # Iterate over pods and set log level
  for pod in $pod_list; do
    logger INFO "Setting log level on pod/$pod"
    response=$("${KUBE_CLI}" exec --namespace "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- \
      curl -XPOST -s -w "%{http_code}" -o /dev/null "0:19000/logging?level=$LOG_LEVEL")
    if [ "$response" -ne 200 ]; then
      logger ERROR "Failed to set log level on pod/$pod (HTTP Status: $response)"
      return 1 # Return failure for individual pod errors
    fi
    logger INFO "Successfully updated log level to $LOG_LEVEL on pod/$pod"
  done

  return 0 # Return success
}

smoke_test() {
  if "${KUBE_CLI}" get service -n default kubernetes --context "${CONTEXT}" >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

# Function to collect dumps
collect_dump() {
  type="$1"
  endpoint=""
  output_dir=$(readlink -f "$OUTPUT_DIR/$type/$CONTEXT")

  # Map the file extension based on the type
  case "$type" in
  stats | clusters | listeners)
    ext="$([ "$FORMAT" = "json" ] && echo "json" || echo "txt")"
    ;;
  config_dump)
    ext=json
    ;;
  logs) ext="log" ;;
  *) ext="txt" ;;
  esac

  mkdir -p "$output_dir" || err "Failed to create directory: $output_dir"

  # Fetch pod list
  pod_list=$("${KUBE_CLI}" get pods --namespace "$SERVICE_NS" --context "$CONTEXT" --selector="app=$SERVICE" -o jsonpath='{.items[*].metadata.name}')
  if [ -z "$pod_list" ]; then
    logger ERROR "No pods found for service: $SERVICE in namespace: $SERVICE_NS"
    return 1
  fi

  # Iterate through the pods and fetch the data
  for pod in $pod_list; do
    output_file="$output_dir/${pod}-${type}.${ext}"
    case "$type" in
    logs)
      container=consul-dataplane # Adjust container name as needed
      logger INFO "Fetching logs from pod/$pod (container: $container)"
      "${KUBE_CLI}" logs --namespace "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "$container" >"$output_file" ||
        logger ERROR "Failed to retrieve logs for pod/$pod"
      ;;
    config_dump)
      endpoint="0:19000/config_dump?include_eds"
      logger INFO "Fetching config dump from pod/$pod at $endpoint"
      "${KUBE_CLI}" exec --namespace "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- \
        curl -s "$endpoint" >"$output_file" ||
        logger ERROR "Failed to fetch config dump for pod/$pod"
      ;;
    stats)
      endpoint="0:19000/stats?format=$FORMAT"
      logger INFO "Fetching stats from pod/$pod at $endpoint"
      "${KUBE_CLI}" exec --namespace "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- \
        curl -s "$endpoint" >"$output_file" ||
        logger ERROR "Failed to fetch stats for pod/$pod"
      ;;
    clusters)
      endpoint="0:19000/clusters?format=$FORMAT"
      logger INFO "Fetching clusters from pod/$pod at $endpoint"
      "${KUBE_CLI}" exec --namespace "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- \
        curl -s "$endpoint" >"$output_file" ||
        logger ERROR "Failed to fetch clusters for pod/$pod"
      ;;
    listeners)
      endpoint="0:19000/listeners?format=$FORMAT"
      logger INFO "Fetching listeners from pod/$pod at $endpoint"
      "${KUBE_CLI}" exec --namespace "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- \
        curl -s "$endpoint" >"$output_file" ||
        logger ERROR "Failed to fetch clusters for pod/$pod"
      ;;
    *)
      logger WARN "Unknown type: $type. Skipping."
      continue
      ;;
    esac

    if [ -f "$output_file" ]; then
      logger INFO "Data saved to $output_file"
    fi
  done

  return 0
}

# Compress function to create a tar.gz file
compress_output() {
  output_dir=$(readlink -f "$OUTPUT_DIR")
  tar_file="${output_dir}-$(date '+%Y-%m-%d_%H-%M-%S').tar.gz"

  logger INFO "Compressing output directory '$output_dir' into tar.gz file: $tar_file"

  # Create the tar.gz archive
  tar -czf "$tar_file" -C "$output_dir" . 2>/dev/null

  if [ $? -eq 0 ]; then
    logger INFO "Compression successful! Archive created at: $tar_file"
  else
    err "Failed to compress files in $output_dir into $tar_file"
  fi
}

## Main
main() {
  # Parse input parameters
  while [ "$#" -gt 0 ]; do
    case "$1" in
    --context)
      CONTEXT="$2"
      shift 2
      ;;
    -s | --service)
      SERVICE="$2"
      shift 2
      ;;
    -n | --namespace)
      SERVICE_NS="$2"
      shift 2
      ;;
    -a | --all)
      ALL=1
      shift
      ;;
    --logs)
      LOGS=1
      ALL=0
      shift
      ;;
    --stats)
      STATS=1
      ALL=0
      shift
      ;;
    --config)
      CONFIG=1
      ALL=0
      shift
      ;;
    --clusters)
      CLUSTERS=1
      ALL=0
      shift
      ;;
    --listeners)
      LISTENERS=1
      ALL=0
      shift
      ;;
    -r | --reset-counters)
      RESET_COUNTERS=1
      shift
      ;;
    -rd | --reset-dump-dir)
      CLEAR_DUMP_DIR=1
      shift
      ;;
    --format)
      FORMAT="$2"
      shift 2
      ;;
    --out-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --log-level)
      LOG_LEVEL="$2"
      shift 2
      ;;
    --compress)
      COMPRESS=1
      shift
      ;;
    --help | -h) usage 0 ;;
    *) err "Unknown option: $1" ;;
    esac
  done
  # Begin execution
  banner
  validate_inputs

  if is_compress_only_run; then
    compress_output
    return 0
  fi

  # Smoke test
  smoke_test || {
    err "Smoke test failed using '${KUBE_CLI}' in context '${CONTEXT}'"
  }

  # Set log level if specified
  if [ -n "$LOG_LEVEL" ]; then
    set_log_level
  fi

  # Reset outlier detection counters if requested
  if [ "$RESET_COUNTERS" -eq 1 ]; then
    reset_outlier_detection "$SERVICE_NS" "$SERVICE" "$CONTEXT" || err "Failed to reset outlier detection counters."
    logger "Outlier detection counters reset successfully."
  fi

  # Execute based on input flags
  [ "$CLEAR_DUMP_DIR" -eq 1 ] && manage_dump_directory "$ACTION_CLEAR"
  manage_dump_directory "$ACTION_CREATE"

  if [ "$ALL" -eq 1 ]; then
    LOGS=1
    CONFIG=1
    STATS=1
    CLUSTERS=1
    LISTENERS=1
    logger INFO "Performing all dump actions."
  fi

  [ "$LOGS" -eq 1 ] && collect_dump logs
  [ "$CONFIG" -eq 1 ] && collect_dump config_dump
  [ "$STATS" -eq 1 ] && collect_dump stats
  [ "$CLUSTERS" -eq 1 ] && collect_dump clusters
  [ "$LISTENERS" -eq 1 ] && collect_dump listeners

  logger INFO "All selected actions completed successfully!"

  # Compress files if the --compress flag was passed
  if [ "$COMPRESS" -eq 1 ]; then
    compress_output
  fi
}

main "$@"
