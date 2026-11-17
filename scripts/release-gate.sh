#!/bin/sh
# Only a commit that passed test.yml is released: the tagged commit itself, or,
# when it is a merge that adds nothing to its second parent (dev merged into
# main: the same tree), that second parent. Run in a checkout of the tagged
# commit with its parents (fetch-depth: 2); needs gh with GH_TOKEN.
#   release-gate.sh COMMIT
set -eu
commit=$1

passed() {
  [ "$(gh run list --repo "$GITHUB_REPOSITORY" --workflow test.yml --commit "$1" --status success --json databaseId --jq length)" -gt 0 ]
}

if passed "$commit"; then
  echo "test.yml passed on $commit, the tagged commit"
  exit 0
fi
if second=$(git rev-parse -q --verify "$commit^2"); then
  if [ "$(git rev-parse "$commit^{tree}")" = "$(git rev-parse "$second^{tree}")" ] && passed "$second"; then
    echo "test.yml passed on $second: the tagged commit $commit merges it with the same tree"
    exit 0
  fi
fi
echo "::error::$commit has no successful run of test.yml (nor a second parent with its tree that has one): push it to dev or main (or open a pull request), wait for test.yml to pass, then re-run this job"
exit 1
