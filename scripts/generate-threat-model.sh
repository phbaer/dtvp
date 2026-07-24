#!/bin/sh
set -eu

repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repository_dir/threat-model-results"}

mkdir -p "$output_dir"
cd "$repository_dir"

uv run --frozen python threatmodel/dtvp.py \
  --report threatmodel/report-template.md \
  --json "$output_dir/model.json" \
  > "$output_dir/report.md"

uv run --frozen python threatmodel/dtvp.py \
  --dfd \
  --colormap \
  > "$output_dir/dfd.dot"

printf 'Generated OWASP pytm analysis in %s\n' "$output_dir"
