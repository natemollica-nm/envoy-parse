#!/usr/bin/env bash

TIMESTAMP_FORMAT='+%d/%m/%Y-%H:%M:%S'

## Logging Functions
function now(){ date "${TIMESTAMP_FORMAT}"; }

function info() {
    echo -ne "$(now) -- ${BLUE}[INFO]${RESET} ${DIM}${1}${RESET}"
}

# Success function to display messages or "ok" by default
function ok() {
    echo -e "${RESET} ${GREEN}✓${RESET}"
}

function warn() {
    echo -e "$(now) -- ${YELLOW}[WARN]${RESET} ${DIM}${1}${RESET} ${YELLOW}[!]${RESET}"
}

function error() {
    echo -e "$(now) -- ${RED}[ERROR]${RESET} ${DIM}${1}${RESET} ${RED}[X]${RESET}" >&2
}

# Define the function to handle print messages with advanced formatting
function print_msg() {
    local msg

    # Print the initial message with timestamp
    printf '%b%s %s\e[0m\n' "${BLUE}[INFO]${RESET}" "$1"
    shift # Remove the initial message from the parameters

    # Loop through the remaining arguments to print additional messages
    for msg in "$@"; do
        printf '%*s%b%s %s\e[0m\n' 10 '' "${LIGHT_GREEN}*==>${RESET}" "$msg"
    done
}