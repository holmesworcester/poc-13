#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)

(
  cd "$root/python"
  PYTHONPATH=. python3 -m unittest -v test_lab.py
)

cargo test --manifest-path "$root/rust/Cargo.toml"

(
  cd "$root/go"
  go test ./...
)

(
  cd "$root/elixir"
  elixir test_lab.exs
)

(
  cd "$root/typescript"
  if [[ ! -x node_modules/.bin/tsc ]]; then
    npm ci
  fi
  npm run typecheck
  npm test
)
