#!/usr/bin/env bash
# Pre-seeds the ollama-compat config blob for hf.co roster tags before
# `ollama pull` ever asks for it (#2728).
#
# Why: alongside the multi-GB weight layers, `ollama pull` fetches a small
# (~480 B) ollama-compat config blob that HuggingFace generates on demand by
# reading the GGUF's metadata. For some repos that generation takes 31-50 s.
# Ollama's per-request deadline is 30 s, so the pull dies with
# "Error: context deadline exceeded" *after* every weight layer -- often
# many GB each -- has already reached 100%. The failure is deterministic
# (HF does not cache the generated config between requests), so retrying
# the same `ollama pull` reproduces it identically every time and just
# re-wastes the download.
#
# curl has no such deadline. Fetching the blob ourselves with a generous
# timeout and dropping it into ollama's blob store by digest makes the
# subsequent `ollama pull` a no-op lookup for that blob -- it already has
# every layer.
#
# Usage: preseed_ollama_config_blob.sh <model-list>
#   <model-list>  one ollama tag per line (blank lines and #-comments
#                 ignored); non-hf.co tags are skipped -- only hf.co repos
#                 have an HF-generated config blob to race against.
#
# Safe to run before every pull, whether or not the blob is actually slow:
# an already-present blob is a single `sudo test -f` and costs nothing.
set -u
B="${OLLAMA_BLOB_DIR:-/var/lib/docker/volumes/ghidra_ollama_models/_data/models/blobs}"
LIST="${1:?usage: preseed_ollama_config_blob.sh <model-list>}"
ok=0; skip=0; fail=0
while read -r TAG; do
  case "$TAG" in ''|\#*) continue;; esac
  case "$TAG" in hf.co/*) ;; *) continue;; esac
  body="${TAG#hf.co/}"; repo="${body%:*}"; tag="${body##*:}"
  man=$(curl -s -m 30 "https://huggingface.co/v2/$repo/manifests/$tag")
  dig=$(printf '%s' "$man" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('config',{}).get('digest',''))
except Exception: print('')" 2>/dev/null)
  [ -z "$dig" ] && { echo "NOMANIFEST $TAG"; fail=$((fail+1)); continue; }
  short="${dig#sha256:}"
  if sudo -n test -f "$B/sha256-$short"; then echo "PRESENT   $TAG"; skip=$((skip+1)); continue; fi
  t0=$(date +%s)
  curl -sL -o /tmp/seed.bin -m 180 "https://huggingface.co/v2/$repo/blobs/$dig" || { echo "FETCHFAIL $TAG"; fail=$((fail+1)); continue; }
  got=$(sha256sum /tmp/seed.bin | cut -d' ' -f1)
  if [ "$got" != "$short" ]; then echo "DIGESTMISMATCH $TAG (want $short got $got)"; fail=$((fail+1)); continue; fi
  sudo -n cp /tmp/seed.bin "$B/sha256-$short"; sudo -n chmod 644 "$B/sha256-$short"
  # A plain `sudo rm -f "$B"/sha256-"$short"-partial*` silently does nothing:
  # the calling user has no read/list permission on $B (root-owned), so the
  # glob is expanded by *this* unprivileged shell before sudo ever runs, finds
  # no match, and passes the literal unexpanded string to `rm -f`, which -f
  # then swallows as a no-op. `find -delete` runs the listing as root instead.
  sudo -n find "$B" -maxdepth 1 -name "sha256-$short-partial*" -delete
  echo "SEEDED    $TAG ($(( $(date +%s) - t0 ))s)"
  ok=$((ok+1))
done < "$LIST"
echo "PRESEED_DONE seeded=$ok present=$skip failed=$fail"
