#!/bin/bash
set -euo pipefail
for candidate in /opt/python/cp311-cp311/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]]; then
    exec "$candidate" /harness/container-build.py "$@"
  fi
done
printf '%s\n' 'No declared Python 3 interpreter exists in the pinned build image' >&2
exit 70
