#!/bin/bash
# Naust installer entry point.
# Bootstraps Python then hands off to setup/boxctl/install.py.

set -e

# Run from repo root regardless of invocation path.
cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/.."

# Must be root.
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root: sudo setup/install.sh"
    exit 1
fi

# Ensure Python 3 is available before we can do anything else.
if ! command -v python3 &>/dev/null; then
    echo "Installing Python 3..."update
    apt-get -qq update
    apt-get -qq install -y python3 python3-pip python3-venv
fi

exec python3 "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/boxctl/install.py" "$@"
