#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '\n== API checks ==\n'
(
  cd "$ROOT/services/api"
  uv sync --locked --all-groups
  uv run --locked ruff check app tests
  uv run --locked ruff format --check app tests
  uv run --locked mypy app
  uv run --locked pytest --cov=app --cov-report=term-missing --cov-fail-under=80
)

printf '\n== Web checks ==\n'
(
  cd "$ROOT/apps/web"
  npm ci
  npm run lint
  npm run typecheck
  npm test
  npm run build
)
