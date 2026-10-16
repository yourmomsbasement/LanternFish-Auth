#!/usr/bin/env bash
# Writes lanternfish-release.json for the files in DIR: what the maintainer
# signs (scripts/sign-releases.sh) and Gates verify before updating.
#   release-manifest.sh VERSION DIR > lanternfish-release.json
set -euo pipefail
version=${1#[vV]}
dir=$2
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "bad version: $1" >&2; exit 1; }
files=$(cd "$dir" && for f in *; do
  [ -f "$f" ] && [ "$f" != lanternfish-release.json ] && [ "$f" != lanternfish-release.json.sig ] || continue
  jq -n --arg name "$f" --arg sha "$(sha256sum "$f" | cut -d' ' -f1)" --argjson size "$(wc -c < "$f" | tr -d ' ')" \
    '{name: $name, sha256: $sha, size: $size}'
done | jq -s 'sort_by(.name)')
jq -n --arg v "$version" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson files "$files" \
  '{schema: 1, product: "lanternfish-gate", version: $v, published: $t, files: $files}'
