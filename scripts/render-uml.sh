#!/usr/bin/env bash
# Render docs/uml/*.puml to SVG with PlantUML.
# Uses a local `plantuml` binary if installed, otherwise the official container image.
set -euo pipefail
cd "$(dirname "$0")/../docs/uml"
mkdir -p svg
if command -v plantuml >/dev/null 2>&1; then
  plantuml -tsvg -o svg ./*.puml
elif command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
  runtime=$(command -v podman || command -v docker)
  "$runtime" run --rm -v "$PWD:/work:Z" -w /work docker.io/plantuml/plantuml:1.2024.7 -tsvg -o svg ./*.puml
else
  echo "Install plantuml (e.g. 'brew install plantuml') or docker/podman." >&2
  exit 1
fi
echo "SVGs written to docs/uml/svg/"
