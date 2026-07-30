#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Safe defaults: local Mealie, read-only MCP, no mutation scope.
export MEALIE_BASE_URL="${MEALIE_BASE_URL:-http://localhost:9000}"
export MEALIE_MCP_ALLOW_MUTATIONS="${MEALIE_MCP_ALLOW_MUTATIONS:-false}"
export MEALIE_MCP_MUTATION_SCOPE="${MEALIE_MCP_MUTATION_SCOPE:-none}"

exec uv run --project "$SCRIPT_DIR" --frozen python "$SCRIPT_DIR/mealie_server.py"
