#!/usr/bin/env bash
#
# release.sh — cut a release.
#
#   bash scripts/release.sh 1.1.0
#
# Sets the version everywhere it appears, runs the tests, commits, and creates
# the tag v1.1.0. Pushing the tag is what publishes the image:
#
#   git push origin main v1.1.0
#
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

die() { printf 'release: %s\n' "$*" >&2; exit 1; }

new="${1:-}"
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "usage: bash scripts/release.sh X.Y.Z"
old="$(tr -d '[:space:]' < VERSION)"

git rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository"
[[ -z "$(git status --porcelain)" ]] || die "commit or stash your changes first"
git rev-parse -q --verify "refs/tags/v${new}" >/dev/null && die "tag v${new} already exists"
grep -Eq "^## ${new//./\\.}([[:space:]]|\$)" CHANGELOG.md || die "add a '## ${new}' section to CHANGELOG.md first (then commit it)"

printf '%s\n' "$new" > VERSION
# The version the compose file and the example settings run by default.
sed -i.bak -E "s/(BOOTSTRAP_VERSION:-)[0-9]+\.[0-9]+\.[0-9]+/\1${new}/" compose.yaml
sed -i.bak -E "s/^(#BOOTSTRAP_VERSION=)[0-9]+\.[0-9]+\.[0-9]+/\1${new}/" .env.example
rm -f compose.yaml.bak .env.example.bak

python3 -m unittest discover -s tests

if [[ "$new" != "$old" ]]; then
  git add VERSION compose.yaml .env.example
  git commit -q -m "Release ${new}"
fi
git tag -a "v${new}" -m "purrbrews-bootstrap ${new}"
printf 'Tagged v%s. Publish it with:\n\n  git push origin HEAD v%s\n' "$new" "$new"
