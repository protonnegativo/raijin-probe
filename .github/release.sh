#!/usr/bin/env bash
# Tags HEAD with the next release and creates its GitHub Release. Usage: release.sh [patch|minor|major] [before-sha]
# With before-sha (the commit before a push), it skips pushes that only touch files the binary does not
# build from. engines.json is embedded in the binary, so a change to it releases. Needs GH_TOKEN (contents: write, actions: write).
set -euo pipefail

bump=${1:-patch}
before=${2:-}

git fetch --tags --force --quiet
if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged: $(git tag --points-at HEAD 'v*' | head -1)"
  exit 0
fi

if [ -n "$before" ] && ! [[ "$before" =~ ^0+$ ]] && git cat-file -e "$before^{commit}" 2>/dev/null; then
  changed=$(git diff --name-only "$before" HEAD | grep -vE '^bench/fixtures/|\.md$|^docs/|^\.github/' || true)
  if [ -z "$changed" ]; then
    echo "only fixtures, docs or .github changed since $before: no release"
    exit 0
  fi
fi

last=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)
if [ -z "$last" ]; then
  next=v0.1.0
else
  IFS=. read -r major minor patch <<< "${last#v}"
  patch=${patch%%[-+]*}
  case "$bump" in
    major) next=v$((major + 1)).0.0 ;;
    minor) next=v$major.$((minor + 1)).0 ;;
    patch) next=v$major.$minor.$((patch + 1)) ;;
    *) echo "unknown bump: $bump" >&2; exit 1 ;;
  esac
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$next" -m "$next"
git push origin "$next"
gh release create "$next" --verify-tag --generate-notes --title "$next"
# Events created with the GITHUB_TOKEN do not start other workflows, so start the binaries build here.
gh workflow run goreleaser.yml -f tag="$next"
echo "released $next"
