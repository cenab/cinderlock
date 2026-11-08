#!/bin/sh
set -eu

CINDERLOCK_HELM_SCRIPT_DIR="${0%/*}"

main() {
  command -v python3 >/dev/null 2>&1 || {
    printf '%s\n' 'Python 3 is required for Helm preparation.' >&2
    exit 2
  }
  exec python3 "${CINDERLOCK_HELM_SCRIPT_DIR}/prepare.py" "${@}"
}

main "${@}"
