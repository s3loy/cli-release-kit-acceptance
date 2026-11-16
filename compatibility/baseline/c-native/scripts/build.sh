#!/usr/bin/env bash
set -euo pipefail

: "${INPUTS_ROOT:?set INPUTS_ROOT to the read-only pinned archive directory}"
: "${CASE_OUT:?set CASE_OUT to the writable case output directory}"
: "${CASE_PYTHON:?set CASE_PYTHON to the explicitly selected built-in image interpreter}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$CASE_PYTHON" "$script_dir/build.py"
