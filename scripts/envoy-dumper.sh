#!/usr/bin/env sh
###############################################################################
# Envoy Dumper: A script for collecting Envoy data (logs, stats, config, etc.)
# from Kubernetes/OpenShift clusters, optionally compressing it into a tarball.
#
# Usage:
#   ./envoy-dumper.sh [parameters] [capture_options] [options]
# Run with --help for more details.
###############################################################################

#------------------------------------------------------------------------------
# Constants & Defaults
#------------------------------------------------------------------------------
OPENSHIFT_CLI=oc
KUBERNETES_CLI=kubectl
IS_OPENSHIFT=0
COMPRESS=0
DEFAULT_CONTEXT=
DEFAULT_ADMIN_API="0:19000"
DEFAULT_OUTPUT_DIR="./envoy-dumper"
DEFAULT_FORMAT="text"
DEFAULT_LOG_LEVEL="info"
DUMP_TYPES="clusters config_dump listeners logs stats tcpdump"
ACTION_CLEAR="clear"
ACTION_CREATE="create"

#------------------------------------------------------------------------------
# Colors
#------------------------------------------------------------------------------
COLOR_INFO="\033[1;36m"   # Bright Cyan
COLOR_BLUE="\033[1;34m"   # Blue
COLOR_WARN="\033[1;33m"   # Yellow
COLOR_ERROR="\033[1;31m"  # Red
COLOR_RESET="\033[0m"     # Reset
INTENSE_BLUE="\033[1;94m" # Bright Blue
INTENSE_CYAN="\033[1;96m" # Bright Cyan
LIGHT_CYAN="\033[96m"     # Light Cyan (added for highlight_message)

#------------------------------------------------------------------------------
# Error Messages
#------------------------------------------------------------------------------
ERR_MISSING_SERVICE="Service name is required. Use '--service' or '-s'."
ERR_MISSING_NAMESPACE="Namespace is required. Use '--namespace' or '-n'."
ERR_FAILED_DIR_CREATION="Failed to create directory: %s"
ERR_CLI_NOT_FOUND="Neither 'oc' nor 'kubectl' is available. Please install one."
ERR_NO_PODS_FOUND="No pods found for service: %s in namespace: %s"

#------------------------------------------------------------------------------
# Default Config / Environment
#------------------------------------------------------------------------------
export ENVOY_ADMIN_API="$DEFAULT_ADMIN_API"
export CONTEXT="$DEFAULT_CONTEXT"       # Kubernetes context
export SERVICE=""                       # Service name
export SERVICE_NS=""                    # Service namespace
export OUTPUT_DIR="$DEFAULT_OUTPUT_DIR" # Directory for output
export CLEAR_DUMP_DIR=0                # Clear output dir flag
export ALL=0                            # Dump all resources
export LOGS=0 STATS=0 CONFIG=0 CLUSTERS=0 LISTENERS=0
export RESET_COUNTERS=0 FORMAT="$DEFAULT_FORMAT" LOG_LEVEL="$DEFAULT_LOG_LEVEL"
export KUBE_CLI=

#------------------------------------------------------------------------------
# print_line: Prints a line of repeated characters
#------------------------------------------------------------------------------
print_line() {
  SCREEN_SIZE=$(( $(tput cols) / 4 ))
  DEFAULT_CHAR='-'
  [ -n "$1" ] && DEFAULT_CHAR="$1"
  [ -n "$2" ] && SCREEN_SIZE="$2"
  printf '%'"$SCREEN_SIZE"'s\n' | tr ' ' "$DEFAULT_CHAR"
}

#------------------------------------------------------------------------------
# banner: Displays a banner with contextual info
#------------------------------------------------------------------------------
banner() {
  terminal_width=$(( $(tput cols) / 4 ))
  title="Consul K8s | Envoy Sidecar Dumper"
  line_char='='
  padding=$(( (terminal_width - ${#title}) / 2 ))
  formatted_title=$(printf "%${padding}s%s\n" "" "$title")

  print_line "$line_char"
  # shellcheck disable=SC2183
  printf "%b%s%b\n" "${COLOR_BLUE}${formatted_title}${COLOR_RESET}"
  service="${SERVICE:-none}"
  service_ns="${SERVICE_NS:-none}"
  kube_context="${CONTEXT:-default}"
  log_level="${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}"
  printf "%$(( padding / 3 ))sService: ${COLOR_WARN}%s${COLOR_RESET} | NS: ${COLOR_WARN}%s${COLOR_RESET} | Ctx: ${COLOR_WARN}%s${COLOR_RESET} | LogLevel: ${COLOR_WARN}%s${COLOR_RESET} | Format: ${COLOR_WARN}%s${COLOR_RESET} \n" \
    "" "$service" "$service_ns" "$kube_context" "$log_level" "$FORMAT"
  print_line "$line_char"
}

#------------------------------------------------------------------------------
# usage: Displays help menu
#------------------------------------------------------------------------------
usage() {
  banner
  cat <<EOF

Usage: $(basename "$0") [parameters] [capture_options] [options]

  Parameters (Required):
    --context              Kubernetes context (e.g., dc1, dc2)
    -s, --service          Kubernetes service deployment name
    -n, --namespace        Kubernetes service namespace

  Capture Options:
    -a, --all              Dump Envoy logs, config, clusters, and listeners
    --logs                 Collect Envoy logs at specified log level
    --stats                Collect Envoy stats
    --config               Collect Envoy configuration
    --clusters             Collect Envoy cluster details
    --listeners            Collect Envoy listener details

  Options:
    --help                 Show this help menu
    --format <fmt>         Output format (text/json; default: $FORMAT)
    --out-dir <dir>        Output directory (default: $OUTPUT_DIR)
    --log-level <level>    Set Envoy logging level (default: $LOG_LEVEL)
    -r, --reset-counters   Reset Envoy counters
    -rd, --reset-dump-dir  Clear the output dump directory
    --compress             Compress output into a tar.gz archive
EOF
  exit "${1:-0}"
}

#------------------------------------------------------------------------------
# highlight_message: Highlights regex matches in a given text
#------------------------------------------------------------------------------
highlight_message() {
  text="$1"; pattern="$2"; color="$3"
  echo "$text" | sed -E "s|(${pattern})|$(printf '%b' "$color")\1$(printf '\033[0m')|g"
}

#------------------------------------------------------------------------------
# logger: Logs messages with optional highlight and colored level tags
#------------------------------------------------------------------------------
logger() {
  level="$1"; shift
  now=$(date '+%d/%m/%Y-%H:%M:%S')
  message="$*"
  message=$(highlight_message "$message" "pod/[a-zA-Z0-9_-]+" "$INTENSE_BLUE")
  message=$(highlight_message "$message" "0:19000/[a-zA-Z0-9_./?=-]+" "$LIGHT_CYAN")
  message=$(highlight_message "$message" "/[a-zA-Z0-9_./-]+" "$INTENSE_CYAN")
  case "$level" in
    INFO)  printf "%s - %b%s%b\n" "$now" "${COLOR_INFO}[INFO]${COLOR_RESET} " "$message" "$COLOR_RESET";;
    WARN)  printf "%s - %b%s%b\n" "$now" "${COLOR_WARN}[WARN]${COLOR_RESET} " "$message" "$COLOR_RESET";;
    ERROR) printf "%s - %b%s%b\n" "$now" "${COLOR_ERROR}[ERROR]${COLOR_RESET}" "$message" "$COLOR_RESET";;
    *)     printf "%s - %b%s%b\n" "$now" "${COLOR_BLUE}[LOG]${COLOR_RESET} " "$message" "$COLOR_RESET";;
  esac
}

#------------------------------------------------------------------------------
# err: Prints an error message and exits
#------------------------------------------------------------------------------
err() {
  message="$1"; exit_code="${2:-1}"
  logger ERROR "$message" >&2
  exit "$exit_code"
}

#------------------------------------------------------------------------------
# verify_installed: Checks if a tool is in PATH
#------------------------------------------------------------------------------
verify_installed() { command -v "$1" >/dev/null 2>&1; }


set_kube_context() {
  if [ -z "$CONTEXT" ]; then
    CONTEXT="$($KUBE_CLI config current-context 2>/dev/null)"
    logger INFO "Using current-context: $CONTEXT"
    return 0
  fi
  logger INFO "Using parameter-set context: $CONTEXT"
}
#------------------------------------------------------------------------------
# set_kube_cli: Sets KUBE_CLI and context if available
#------------------------------------------------------------------------------
set_kube_cli() {
  cli_tool="$1"
  KUBE_CLI="$(which "$cli_tool")"
  set_kube_context
}

#------------------------------------------------------------------------------
# detect_openshift_resources: Checks if cluster is OpenShift
#------------------------------------------------------------------------------
detect_openshift_resources() {
  if $KUBE_CLI api-resources | grep -q "project.openshift.io"; then
    logger INFO "OpenShift-specific resources detected."; IS_OPENSHIFT=1
  else
    logger WARN "No OpenShift-specific resources found. Assuming vanilla K8s."
    IS_OPENSHIFT=0
  fi
}

#------------------------------------------------------------------------------
# detect_kube_cli: Determines which CLI (oc/kubectl) to use
#------------------------------------------------------------------------------
detect_kube_cli() {
  logger INFO "Detecting K8s CLI tool..."
  if verify_installed "$OPENSHIFT_CLI"; then
    set_kube_cli "$OPENSHIFT_CLI"
    detect_openshift_resources
    if [ "$IS_OPENSHIFT" -eq 0 ] && verify_installed "$KUBERNETES_CLI"; then
      set_kube_cli "$KUBERNETES_CLI"
    elif [ "$IS_OPENSHIFT" -eq 0 ]; then
      err "$ERR_CLI_NOT_FOUND"
    fi
    return 0
  fi
  if verify_installed "$KUBERNETES_CLI"; then
    set_kube_cli "$KUBERNETES_CLI"
    IS_OPENSHIFT=0; return 0
  fi
  err "$ERR_CLI_NOT_FOUND"
}

#------------------------------------------------------------------------------
# is_single_operation_run: Checks if only one specified flag is on
#------------------------------------------------------------------------------
is_single_operation_run() {
  primary_flag="$1"; shift
  excluded_flags="$*"
  eval "primary_flag_value=\${$primary_flag}"
  [ "$primary_flag_value" -ne 1 ] && return 1
  for ef in $excluded_flags; do
    eval "efv=\${$ef}"
    [ "$efv" -ne 0 ] && return 1
  done
  return 0
}

is_compress_only_run() { is_single_operation_run COMPRESS LOGS STATS CONFIG CLUSTERS LISTENERS ALL RESET_COUNTERS; }
is_reset_counters_only_run() { is_single_operation_run RESET_COUNTERS LOGS STATS CONFIG CLUSTERS LISTENERS ALL COMPRESS; }

#------------------------------------------------------------------------------
# smoke_test: Quickly tests CLI access by checking a default resource
#------------------------------------------------------------------------------
smoke_test() { $KUBE_CLI get service -n default kubernetes --context "$CONTEXT" >/dev/null 2>&1; }

#------------------------------------------------------------------------------
# validate_inputs: Ensures required data is provided
#------------------------------------------------------------------------------
validate_inputs() {
  if is_compress_only_run; then
    logger INFO "Compress-only mode. Skipping service/namespace validation."; return 0
  fi
  if is_reset_counters_only_run; then
    logger INFO "Reset-counters-only mode. Skipping service/namespace validation."; return 0
  fi
  if [ "$CLEAR_DUMP_DIR" -eq 1 ]; then
    logger INFO "Reset-dump-dir mode. Skipping service/namespace validation."; return 0
  fi
  detect_kube_cli
  [ -z "$KUBE_CLI" ] && err "$ERR_CLI_NOT_FOUND"
  [ -z "$SERVICE" ] && err "$ERR_MISSING_SERVICE"
  [ -z "$SERVICE_NS" ] && err "$ERR_MISSING_NAMESPACE"
  smoke_test || err "Smoke test failed using '$KUBE_CLI' in context '$CONTEXT'"
}

#------------------------------------------------------------------------------
# get_pods: Retrieves pods matching a service's label
#------------------------------------------------------------------------------
get_pods() {
  service_name="$1"; service_ns="$2"
  selector_key=app; selector_value="$service_name"
  case "$service_name" in
    *-gateway*) selector_key=component; selector_value="${service_name#consul-}";;
  esac
  pods=$($KUBE_CLI get pods -n "$service_ns" --context "$CONTEXT" -l "${selector_key}=${selector_value}" -o jsonpath="{.items[*].metadata.name}" 2>/dev/null)
  if [ -z "$pods" ]; then
    logger ERROR "No pods found for service: $service_name in ns: $service_ns"
    # shellcheck disable=SC2059
    err "$(printf "$ERR_NO_PODS_FOUND" "$service_name" "$service_ns")"
  fi
  echo "$pods"
}

#------------------------------------------------------------------------------
# manage_dump_directory: Clears or creates the dump directories
#------------------------------------------------------------------------------
manage_dump_directory() {
  action="$1"
  case "$action" in
    "$ACTION_CLEAR")
      logger INFO "Clearing contents in $OUTPUT_DIR/"
      for dump in $DUMP_TYPES; do
        path="$OUTPUT_DIR/$dump"
        if [ -d "$path" ]; then
          rm -rf "${path:?}"/* || err "Failed to clear: $path"
          logger INFO "Cleared: $path"
        fi
      done
    ;;
    "$ACTION_CREATE")
      logger INFO "Creating dump directories in $OUTPUT_DIR/"
      # shellcheck disable=SC2059
      mkdir -p "$OUTPUT_DIR" || err "$(printf "$ERR_FAILED_DIR_CREATION" "$OUTPUT_DIR")"
      for dump in $DUMP_TYPES; do
        path="$OUTPUT_DIR/$dump/$CONTEXT"
        # shellcheck disable=SC2059
        mkdir -p "$path" || err "$(printf "$ERR_FAILED_DIR_CREATION" "$path")"
      done
    ;;
    *) err "Invalid action: $action";;
  esac
}

#------------------------------------------------------------------------------
# reset_outlier_detection: Resets Envoy outlier detection counters
#------------------------------------------------------------------------------
reset_outlier_detection() {
  namespace="$1"; service="$2"; context="$3"
  logger INFO "Resetting outlier detection counters for $namespace/$service"
  pod_list="$(get_pods "$service" "$namespace")" || return 1
  OUTLIER_COUNTER_RESET_ENDPOINT="runtime_reset"
  for pod in $pod_list; do
    logger INFO "Resetting counters on pod/$pod"
    $KUBE_CLI exec -n "$namespace" --context "$context" "pod/$pod" -c "${service#consul-}" -- \
      curl -s -XPOST "$ADMIN_API/$OUTLIER_COUNTER_RESET_ENDPOINT" >/dev/null 2>&1 || {
      logger ERROR "Failed to reset counters on $pod"; return 1
    }
    logger INFO "Counters reset on $pod"
  done
}

#------------------------------------------------------------------------------
# set_log_level: Adjusts Envoy's log level
#------------------------------------------------------------------------------
# Fallback function for setting log level via local port-forward
set_log_level_via_port_forward() {
  pod="$1"
  namespace="$2"
  local_port="$3"      # e.g., 19001
  remote_port="$4"     # e.g., 19000
  path_only="$5"       # e.g., /logging?level=trace

  # Start port-forward in background
  "$KUBE_CLI" port-forward \
    --namespace "$namespace" \
    "pod/$pod" \
    "$local_port:$remote_port" >/dev/null 2>&1 &
  pf_pid=$!

  # Define a cleanup function that kills the background process
  cleanup_port_forward() {
    kill "$pf_pid" 2>/dev/null
    wait "$pf_pid" 2>/dev/null
  }

  # Trap signals (and EXIT) to ensure we always clean up
  trap 'cleanup_port_forward' INT TERM HUP EXIT

  # Give port-forward a moment to initialize
  sleep 2

  # Perform the POST, capturing the numeric HTTP status code
  http_code="$(curl -XPOST -s -w '%{http_code}' -o /dev/null "http://127.0.0.1:$local_port$path_only")"

  # Cleanup now that we have the data
  cleanup_port_forward
  trap - INT TERM HUP EXIT

  # Return the HTTP status code by echoing it
  echo "$http_code"
}

set_log_level() {
  logger INFO "Setting Envoy log level to $( echo "${LOG_LEVEL}" | tr '[:lower:]' '[:upper:]') for $SERVICE in $SERVICE_NS"
  pod_list="$(get_pods "$SERVICE" "$SERVICE_NS")" || return 1

  for pod in $pod_list; do
    pod_safe=$(echo "$pod" | sed 's/[^a-zA-Z0-9.-]//g')
    [ -z "$pod_safe" ] && { logger ERROR "Skipping invalid pod: $pod"; continue; }

    logger INFO "Setting log level on pod/$pod"

    # 1) Try in-pod curl first:
    response=$(
      "$KUBE_CLI" exec -n "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" \
        -c "${SERVICE#consul-}" \
        -- curl -XPOST -s -w "%{http_code}" -o /dev/null "0:19000/logging?level=$LOG_LEVEL" 2>/dev/null
    )

    # If the in-pod curl didn't work or wasn't HTTP 200, use fallback
    if [ "$?" -ne 0 ] || [ "$response" != "200" ]; then
      logger WARN "curl not found or request failed on pod/$pod (HTTP Response Code: '$response'). Falling back to port-forward..."
      # 2) Fallback: port-forward from local 19001 => remote 19000
      path_only="/logging?level=$LOG_LEVEL"
      fallback_code="$(set_log_level_via_port_forward "$pod" "$SERVICE_NS" 19001 19000 "$path_only")"

      if [ "$fallback_code" != "200" ]; then
        logger ERROR "Failed to set log level on $pod via fallback (HTTP Response Code: '$fallback_code')."
        return 1
      fi
      logger INFO "Log level successfully updated to $LOG_LEVEL on $pod (fallback)."
    else
      logger INFO "Log level successfully updated to $LOG_LEVEL on $pod (in-pod)."
    fi
  done
}


#------------------------------------------------------------------------------
# collect_dump: Collects various data (logs, stats, config, etc.) from pods
#------------------------------------------------------------------------------
# Fallback function that uses port-forward
collect_envoy_via_port_forward() {
  pod="$1"
  namespace="$2"
  local_port="$3"      # e.g., 19001
  remote_port="$4"     # e.g., 19000
  endpoint="$5"        # e.g., /stats?format=json

  # Start port-forward in the background
  "$KUBE_CLI" port-forward \
    --namespace "$namespace" \
    "pod/$pod" \
    "$local_port:$remote_port" >/dev/null 2>&1 &
  pf_pid=$!

  # Define a cleanup function that kills the background process
  cleanup_port_forward() {
    kill "$pf_pid" 2>/dev/null
    wait "$pf_pid" 2>/dev/null
  }

  # Trap signals (and EXIT) to ensure we always clean up
  trap 'cleanup_port_forward' INT TERM HUP EXIT

  # Give port-forward a moment to start
  sleep 2

  # Capture the local curl output as a string
  envoy_output="$(curl -s "http://127.0.0.1:$local_port$endpoint")"

  # Clean up now that we have the data
  cleanup_port_forward

  # Disable the trap so it doesn’t trigger again on normal exit
  trap - INT TERM HUP EXIT

  # Return the output by echoing it to stdout | Use `printf` to escape the JSON carefully
  printf '%s' "$envoy_output"
}

collect_dump() {
  type="$1"
  dir="$OUTPUT_DIR/$type/$CONTEXT"

  # Choose file extension
  case "$type" in
    stats|clusters|listeners) [ "$FORMAT" = "json" ] && ext="json" || ext="txt" ;;
    config_dump) ext="json" ;;
    logs) ext="log" ;;
    *) ext="txt" ;;
  esac

  mkdir -p "$dir" || { logger ERROR "Failed to create: $dir"; return 1; }
  pod_list="$(get_pods "$SERVICE" "$SERVICE_NS")" || return 1

  for pod in $pod_list; do
    pod_safe=$(echo "$pod" | sed 's/[^a-zA-Z0-9.-]//g')
    [ -z "$pod_safe" ] && { logger ERROR "Skipping invalid pod: $pod"; continue; }
    outfile="${dir}/${pod_safe}-${type}.${ext}"

    # Decide what path we need
    case "$type" in
      logs)
        log_dump_container=consul-dataplane
        case "$SERVICE" in
          *-gateway*) log_dump_container="${service_name#consul-}";;
        esac
        logger INFO "Fetching logs from $pod"
        pod_output="$($KUBE_CLI logs -n "$SERVICE_NS" --context "$CONTEXT" \
          "pod/$pod" -c "$log_dump_container" 2>/dev/null)"
        ;;

      config_dump)
        path_only="/config_dump?include_eds"
        endpoint="${ENVOY_ADMIN_API}${path_only}"
        logger INFO "Fetching config_dump from $pod ($endpoint)"
        pod_output="$($KUBE_CLI exec -n "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- curl -s "$endpoint" 2>/dev/null)"
        # If it fails, fallback
        if [ $? -ne 0 ] || [ -z "$pod_output" ]; then
          logger WARN "curl not found or request failed on pod/$pod; using port-forward (fallback)."
          pod_output="$(collect_envoy_via_port_forward \
            "$pod" \
            "$SERVICE_NS" \
            19001 \
            19000 \
            "$path_only")"
        fi
        ;;

      stats)
        path_only="/stats?format=$FORMAT"
        endpoint="${ENVOY_ADMIN_API}${path_only}"
        logger INFO "Fetching stats from $pod ($endpoint)"
        pod_output="$($KUBE_CLI exec -n "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- curl -s "$endpoint" 2>/dev/null)"
        if [ $? -ne 0 ] || [ -z "$pod_output" ]; then
          logger WARN "curl not found or request failed on pod/$pod; using port-forward (fallback)."
          pod_output="$(collect_envoy_via_port_forward \
            "$pod" \
            "$SERVICE_NS" \
            19001 \
            19000 \
            "$path_only")"
        fi
        ;;

      clusters)
        path_only="/clusters?format=$FORMAT"
        endpoint="${ENVOY_ADMIN_API}${path_only}"
        logger INFO "Fetching clusters from $pod ($endpoint)"
        pod_output="$($KUBE_CLI exec -n "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- curl -s "$endpoint" 2>/dev/null)"
        if [ $? -ne 0 ] || [ -z "$pod_output" ]; then
          logger WARN "curl not found or request failed on pod/$pod; using port-forward (fallback)."
          pod_output="$(collect_envoy_via_port_forward \
            "$pod" \
            "$SERVICE_NS" \
            19001 \
            19000 \
            "$path_only")"
        fi
        ;;

      listeners)
        path_only="/listeners?format=$FORMAT"
        endpoint="${ENVOY_ADMIN_API}${path_only}"
        logger INFO "Fetching listeners from $pod ($endpoint)"
        pod_output="$($KUBE_CLI exec -n "$SERVICE_NS" --context "$CONTEXT" "pod/$pod" -c "${SERVICE#consul-}" -- curl -s "$endpoint" 2>/dev/null)"
        if [ $? -ne 0 ] || [ -z "$pod_output" ]; then
          logger WARN "curl not found or request failed on pod/$pod; using port-forward (fallback)."
          pod_output="$(collect_envoy_via_port_forward \
            "$pod" \
            "$SERVICE_NS" \
            19001 \
            19000 \
            "$path_only")"
        fi
        ;;

      *)
        logger WARN "Unknown type: $type"
        continue
        ;;
    esac

    # Write output if we have it
    if [ -n "$pod_output" ]; then
      # Use `printf` to escape the JSON carefully
      [ "$ext" = json ] && \
          printf '%s' "$pod_output" | jq --raw-input --raw-output . >"${outfile}" || \
          echo "$pod_output" > "$outfile"
      logger INFO "Data saved to $outfile"
    else
      logger WARN "No output from $pod. Skipping file."
    fi
  done
}


#------------------------------------------------------------------------------
# compress_output: Creates a tarball of OUTPUT_DIR
#------------------------------------------------------------------------------
compress_output() {
  out_dir=$(readlink -f "$OUTPUT_DIR")
  tar_file="${out_dir}-$(date '+%Y-%m-%d_%H-%M-%S').tar.gz"
  logger INFO "Compressing '$out_dir' to '$tar_file'"
  tar -czf "$tar_file" -C "$out_dir" . 2>/dev/null || err "Failed to compress: $out_dir"
  logger INFO "Compression successful: $tar_file"
}

#------------------------------------------------------------------------------
# manage_operations: Handles directory setup, compression, reset counters, etc.
#------------------------------------------------------------------------------
manage_operations() {
  if is_compress_only_run; then compress_output; return 0; fi
  if is_reset_counters_only_run; then
    reset_outlier_detection "$SERVICE_NS" "$SERVICE" "$CONTEXT" || err "Failed reset outlier detection."
    return 0
  fi

  [ "$LOG_LEVEL" != "info" ] && set_log_level

  if [ "$RESET_COUNTERS" -eq 1 ]; then
    reset_outlier_detection "$SERVICE_NS" "$SERVICE" "$CONTEXT" || err "Failed reset counters."
    logger INFO "Outlier detection counters reset successfully."
  fi
  # shellcheck disable=SC2015
  [ "$CLEAR_DUMP_DIR" -eq 1 ] && manage_dump_directory "$ACTION_CLEAR" || manage_dump_directory "$ACTION_CREATE"
}

#------------------------------------------------------------------------------
# main: Orchestrates script execution flow
#------------------------------------------------------------------------------
main() {
  # Each multi-argument case collapses into one line by using a quick inline check. The short flags
  # (-s, -n, etc.) still work as before. This keeps the script length minimal but introduces
  # minimal logic for detecting the = sign
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --context|--context=*)        CONTEXT="$( [ "${1#*=}" != "$1" ] && echo "${1#*=}" || echo "$2" )"; [ "${1#*=}" = "$1" ] && shift 2 || shift;;
      --envoy-admin-addr|--envoy-admin-addr=*) ENVOY_ADMIN_API="$( [ "${1#*=}" != "$1" ] && echo "${1#*=}" || echo "$2" )"; [ "${1#*=}" = "$1" ] && shift 2 || shift;;
      -s|--service|--service=*)     SERVICE="$( [ "${1#*=}" != "$1" ] && echo "${1#*=}" || echo "$2" )"; [ "${1#*=}" = "$1" ] && shift 2 || shift;;
      -n|--namespace|--namespace=*) SERVICE_NS="$( [ "${1#*=}" != "$1" ] && echo "${1#*=}" || echo "$2" )"; [ "${1#*=}" = "$1" ] && shift 2 || shift;;
      -a|--all)                     ALL=1; shift;;
      --logs)                       LOGS=1; ALL=0; shift;;
      --stats)                      STATS=1; ALL=0; shift;;
      --config)                     CONFIG=1; ALL=0; shift;;
      --clusters)                   CLUSTERS=1; ALL=0; shift;;
      --listeners)                  LISTENERS=1; ALL=0; shift;;
      -r|--reset-counters)          RESET_COUNTERS=1; shift;;
      -rd|--reset-dump-dir)         CLEAR_DUMP_DIR=1; shift;;
      --format|--format=*)          FORMAT="$( [ "${1#*=}" != "$1" ] && echo "${1#*=}" || echo "$2" )"; [ "${1#*=}" = "$1" ] && shift 2 || shift;;
      --out-dir|--out-dir=*)        OUTPUT_DIR="$( [ "${1#*=}" != "$1" ] && echo "${1#*=}" || echo "$2" )"; [ "${1#*=}" = "$1" ] && shift 2 || shift;;
      --log-level|--log-level=*)    LOG_LEVEL="$( [ "${1#*=}" != "$1" ] && echo "${1#*=}" || echo "$2" )"; [ "${1#*=}" = "$1" ] && shift 2 || shift;;
      --compress)                   COMPRESS=1; shift;;
      --help|-h)                    usage 0;;
      *)                            err "Unknown option: $1";;
    esac
  done
  validate_inputs && clear
  banner
  manage_operations


  [ "$ALL" -eq 1 ] && { LOGS=1; CONFIG=1; STATS=1; CLUSTERS=1; LISTENERS=1; }

  [ "$LOGS" -eq 1 ]      && collect_dump logs
  [ "$CONFIG" -eq 1 ]    && collect_dump config_dump
  [ "$STATS" -eq 1 ]     && collect_dump stats
  [ "$CLUSTERS" -eq 1 ]  && collect_dump clusters
  [ "$LISTENERS" -eq 1 ] && collect_dump listeners

  logger INFO "All selected actions completed!"
  [ "$COMPRESS" -eq 1 ] && compress_output
}


main "$@"
