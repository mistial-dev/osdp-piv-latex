#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

base_ref="${BASE:-${1:-}}"
if [[ -z "$base_ref" ]]; then
  echo "Usage: make redline BASE=<git-ref>" >&2
  exit 2
fi

for tool in git tar latexpand latexdiff latexmk; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required tool: $tool" >&2
    echo "For TeX Live, install the redline tools with: tlmgr install latexdiff latexpand" >&2
    exit 2
  fi
done

base_commit="$(git rev-parse --verify "${base_ref}^{commit}")"
base_short="$(git rev-parse --short=12 "$base_commit")"
current_short="$(git rev-parse --short=12 HEAD)"

redline_dir="$repo_root/build/redline"
scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/osdp-piv-redline.XXXXXX")"
trap 'rm -rf "$scratch_dir"' EXIT

mkdir -p "$redline_dir" "$scratch_dir/base"
git archive "$base_commit" | tar -x -C "$scratch_dir/base"

(
  cd "$scratch_dir/base"
  latexpand main.tex
) > "$redline_dir/base.tex"

latexpand main.tex > "$redline_dir/current.tex"

latexdiff \
  --encoding=utf8 \
  --type=UNDERLINE \
  "$redline_dir/base.tex" \
  "$redline_dir/current.tex" \
  > "$redline_dir/osdp-piv-proposal-redline.tex"

perl -0pi -e \
  's/\\date\{\\today\}/\\date\{Redline: '"$base_short"' to '"$current_short"' working tree\\\\\\today\}/' \
  "$redline_dir/osdp-piv-proposal-redline.tex"

latexmk \
  -xelatex \
  -interaction=nonstopmode \
  -halt-on-error \
  -outdir="$redline_dir" \
  "$redline_dir/osdp-piv-proposal-redline.tex"

echo "Redline PDF: $redline_dir/osdp-piv-proposal-redline.pdf"
