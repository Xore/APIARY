#!/usr/bin/env bash
# Promote a tagged commit to the branch the home stacks deploy from (#1507).
#
# The policy is release/tag promotion, but Arcane cannot track a tag: its ref
# resolver prefixes refs/heads/ onto whatever it is given, so a sync pointed at
# a tag fails with a bare 500. Verified live on 2026-08-25 against the pihole
# sync -- the same limitation docs/ARCANE-GIT-SYNC.md already records for the
# build-context resolver, which is presumably the same code.
#
# So the tag is the release and `production` is a pointer at it. Promotion is a
# fast-forward of that pointer onto an immutable, signed-off commit; rollback
# is the same command naming an earlier tag. What deploys is always a tagged
# commit, which is what the policy asked for.
#
#   scripts/promote-release.sh v0.1.0        promote that tag
#   scripts/promote-release.sh --list        show what is deployed vs available
#
# Promoting does not deploy. Arcane's syncs are autoSync:false for the 35
# stacks that build an image, so a promotion makes the release *available* and
# an operator still triggers sync -> build -> redeploy per stack. The three
# pull-only stacks (honeypot-elk, honeypot-keycloak, pihole) do follow it
# automatically -- see the manifest.
set -euo pipefail

BRANCH="${PROMOTE_BRANCH:-production}"
REMOTE="${PROMOTE_REMOTE:-origin}"

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

git fetch --quiet "$REMOTE" --tags

current() {
  git rev-parse --quiet --verify "refs/remotes/$REMOTE/$BRANCH" 2>/dev/null || true
}

if [ "${1:-}" = "--list" ] || [ $# -eq 0 ]; then
  head="$(current)"
  if [ -n "$head" ]; then
    echo "deployed ($BRANCH): $(git describe --tags --exact-match "$head" 2>/dev/null || echo "$head, not a tagged commit")"
  else
    echo "deployed ($BRANCH): branch does not exist yet"
  fi
  echo
  echo "available tags (newest first):"
  git tag --list --sort=-creatordate | head -10 | sed 's/^/  /'
  [ $# -eq 0 ] && { echo; usage; }
  exit 0
fi

TAG="$1"

if ! git rev-parse --quiet --verify "refs/tags/$TAG" >/dev/null; then
  echo "no such tag: $TAG" >&2
  echo "run with --list to see what is available" >&2
  exit 1
fi

target="$(git rev-parse "refs/tags/$TAG^{commit}")"
head="$(current)"

# A tag that is not on main is a tag of something that never passed CI.
if ! git merge-base --is-ancestor "$target" "refs/remotes/$REMOTE/main" 2>/dev/null; then
  echo "$TAG is not an ancestor of $REMOTE/main -- refusing to promote a commit that is not on main" >&2
  exit 1
fi

if [ "$head" = "$target" ]; then
  echo "$BRANCH is already at $TAG ($target)"
  exit 0
fi

if [ -n "$head" ]; then
  if git merge-base --is-ancestor "$head" "$target"; then
    echo "promoting $BRANCH: $(git describe --tags --always "$head") -> $TAG"
  else
    # Rolling back is a legitimate operation and is not a fast-forward, so it
    # is allowed -- but say so out loud rather than doing it silently.
    echo "ROLLING BACK $BRANCH: $(git describe --tags --always "$head") -> $TAG (not a fast-forward)"
  fi
else
  echo "creating $BRANCH at $TAG"
fi

git push "$REMOTE" "$target:refs/heads/$BRANCH" ${head:+--force-with-lease="refs/heads/$BRANCH:$head"}

echo "done. $BRANCH now points at $TAG ($target)"
echo
echo "The three pull-only stacks follow this automatically within their sync"
echo "interval. Everything that builds an image still needs, per stack:"
echo "  sync -> build -> redeploy   (see docs/ARCANE-GIT-SYNC.md)"
