#!/usr/bin/env bash

[[ "$(uname -m)" =~ aarch64|arm64 ]] && echo arm64 || echo amd64