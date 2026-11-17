#!/bin/sh
# Prints docs_only=true when every path a push or pull request changes is docs
# (*.md, docs/, local/), read by no test but cmd/reqcove's; then test.yml
# runs only its light jobs. Anything uncertain prints docs_only=false: an event
# other than these two, a commit missing (a new branch's first push has no
# before), a force-push, no change at all.
#   ci-docs-only.sh push BEFORE AFTER
#   ci-docs-only.sh pull_request BASE HEAD
# skills/reqcove/SKILL.md counts as docs though reqcove embeds it: its tests are
# cmd/reqcove's too.
set -u
event=${1:-} base=${2:-} head=${3:-}

answer() { echo "docs_only=$1"; exit 0; }

{ git cat-file -e "$base^{commit}" && git cat-file -e "$head^{commit}"; } 2>/dev/null || answer false
case $event in
  push) git merge-base --is-ancestor "$base" "$head" || answer false; range="$base..$head" ;;
  pull_request) range="$base...$head" ;; # what the pull request changes since it left its base
  *) answer false ;;
esac
# No renames: a file moved into docs/ is still a file gone from where it was.
files=$(git diff --no-renames --name-only "$range") || answer false
[ -n "$files" ] || answer false
echo "$files" >&2
echo "$files" | while IFS= read -r f; do
  case $f in
    *.md | docs/* | local/*) ;;
    *) echo "not docs: $f" >&2; exit 1 ;;
  esac
done || answer false
answer true
