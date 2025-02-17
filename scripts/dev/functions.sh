#!/usr/bin/env bash

FUNC_DIR="$(dirname "$(dirname "${BASH_SOURCE[0]}")")/functions"

func_sources=$(find "${FUNC_DIR}" -mindepth 1 -maxdepth 1 -type f ! -name "*architecture.sh" | sort -n)

for src in $func_sources; do
   source $src
done