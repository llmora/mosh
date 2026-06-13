#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_DOCKER=0
FORCE_DOCKER=0

usage() {
  cat <<'EOF'
Usage: ./scripts/setup.sh [--skip-docker] [--force-docker] [--help]

Sets up Model-driven Open Security Harness for local use.

Options:
  --skip-docker   Install Python package only; do not build tool images.
  --force-docker  Rebuild Docker tool images even when they look current.
  --help          Show this help text.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --skip-docker)
      SKIP_DOCKER=1
      ;;
    --force-docker)
      FORCE_DOCKER=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_command python3

python3 - <<'PY'
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required.")
PY

if [ ! -d "$ROOT_DIR/.venv" ]; then
  echo "Creating .venv"
  python3 -m venv "$ROOT_DIR/.venv"
fi

# shellcheck disable=SC1091
source "$ROOT_DIR/.venv/bin/activate"

echo "Installing Model-driven Open Security Harness in editable mode"
python -m pip install --upgrade pip
python -m pip install -e "$ROOT_DIR"

if [ "$SKIP_DOCKER" -eq 1 ]; then
  echo "Skipping Docker image build"
  exit 0
fi

require_command docker

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but the daemon is not available." >&2
  exit 1
fi

image_needs_rebuild() {
  local image="$1"
  shift

  if [ "$FORCE_DOCKER" -eq 1 ]; then
    echo "$image: forced rebuild requested"
    return 0
  fi

  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "$image: image missing"
    return 0
  fi

  local created
  created="$(docker image inspect -f '{{.Created}}' "$image")"

  python3 - "$created" "$@" <<'PY'
from __future__ import annotations

import datetime as dt
import os
import pathlib
import re
import sys

created_raw = sys.argv[1]
source_paths = [pathlib.Path(item) for item in sys.argv[2:]]

normalized = created_raw.replace("Z", "+00:00")
normalized = re.sub(r"(\.\d{6})\d+(?=[+-])", r"\1", normalized)
created = dt.datetime.fromisoformat(normalized).timestamp()

for source_path in source_paths:
    if not source_path.exists():
        print(f"{source_path}: missing source path")
        sys.exit(0)

    paths = [source_path]
    if source_path.is_dir():
        paths = [pathlib.Path(root) / name for root, _, files in os.walk(source_path) for name in files]

    for path in paths:
        if path.stat().st_mtime > created:
            print(f"{path}: newer than image")
            sys.exit(0)

sys.exit(1)
PY
}

build_image_if_needed() {
  local image="$1"
  local dockerfile="$2"
  shift 2

  if image_needs_rebuild "$image" "$dockerfile" "$@"; then
    echo "Building $image"
    docker build -t "$image" -f "$dockerfile" "$ROOT_DIR"
  else
    echo "$image: current"
  fi
}

build_image_if_needed \
  "mosh-discovery-tools:latest" \
  "$ROOT_DIR/tools/discovery/Dockerfile" \
  "$ROOT_DIR/tools/discovery/katana-form-config.yaml" \
  "$ROOT_DIR/tools/discovery/js-endpoint-extractor/package.json" \
  "$ROOT_DIR/tools/discovery/js-endpoint-extractor/js-endpoint-extractor.mjs"

build_image_if_needed \
  "mosh-security-tools:latest" \
  "$ROOT_DIR/tools/security/Dockerfile"

echo "Setup complete. Activate the environment with: source .venv/bin/activate"
