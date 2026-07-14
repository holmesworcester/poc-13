#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
command -v cloc >/dev/null || {
  echo "measure_loc.sh requires cloc" >&2
  exit 1
}

measure() {
  local label=$1
  shift
  local row
  row=$(cloc --csv --quiet "$@" | awk -F, '$2 == "SUM" {print $3 "," $4 "," $5}')
  local blank comment code
  IFS=, read -r blank comment code <<<"$row"
  local physical
  physical=$(wc -l "$@" | awk 'END {print $1}')
  printf '%-20s %8d %8d %8d %10d\n' "$label" "$code" "$blank" "$comment" "$physical"
}

printf '%-20s %8s %8s %8s %10s\n' Group Code Blank Comment Physical
measure "Python production" "$root/python/lab_kernel.py" "$root/python/lab_runtime.py"
measure "Python tests" "$root/python/test_lab.py"
measure "Elixir production" "$root/elixir/kernel.exs" "$root/elixir/runtime.exs"
measure "Elixir tests" "$root/elixir/test_lab.exs"
measure "TypeScript production" "$root/typescript/model.ts" "$root/typescript/kernel.ts" "$root/typescript/runtime.ts"
measure "TypeScript tests" "$root/typescript/lab.test.ts"
measure "Go production" "$root/go/model.go" "$root/go/kernel.go" "$root/go/runtime.go"
measure "Go tests" "$root/go/lab_test.go"
measure "Rust production" "$root/rust/src/lib.rs" "$root/rust/src/kernel.rs" "$root/rust/src/runtime.rs"
measure "Rust tests" "$root/rust/tests/lab.rs"
