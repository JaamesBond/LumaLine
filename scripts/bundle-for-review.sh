#!/usr/bin/env bash
# Produce a SAFE tarball of the repo for an external security reviewer.
#
# Uses `git archive`, which includes ONLY git-tracked files — so no .env, no
# supabase/functions/.env, no .secrets/, nothing gitignored can ever be bundled, even by
# accident. Do NOT `zip`/`tar`/`cp -r` the working directory to share it: that would sweep
# in the gitignored .env files (which hold real Stripe keys). Always use this script.
#
# Usage: bash scripts/bundle-for-review.sh   →   lumaline-review-<shortsha>.tar.gz
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SHA="$(git rev-parse --short HEAD)"
OUT="lumaline-review-${SHA}.tar.gz"

git archive --format=tar.gz -o "$OUT" HEAD

echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
echo "Verifying the bundle carries no secret files…"
# Match real env files (.env, .env.local, supabase/functions/.env) and .secrets/, but NOT
# the safe .env.example placeholder template (which SHOULD ship to the reviewer).
if tar -tzf "$OUT" | grep -iE '(^|/)\.env(\.local)?$|\.secrets/' ; then
  echo "FATAL: bundle contains an env/secret file — DO NOT SHARE. Aborting." >&2
  rm -f "$OUT"
  exit 1
fi
echo "OK: no .env / .secrets in the bundle. Safe to hand to the reviewer."
echo "Also give them: docs/ops/t7-external-review-brief.md (the scope + threat model)."
