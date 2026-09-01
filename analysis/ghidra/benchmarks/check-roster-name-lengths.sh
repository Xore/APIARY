#!/usr/bin/env bash
# #2738 preflight: catch a roster entry Ollama's client-side hf.co name
# validation will reject before a sweep wastes time discovering it. Ollama
# 0.32.13, bisected live: `ollama pull hf.co/<owner>/<repo>:<tag>` fails
# with a bare `400 Bad Request: invalid model name` in under a second --
# before any network transfer -- whenever the repo-name segment (between
# the owner slash and the colon) exceeds 80 characters. See
# oversized-model-aliases.tsv for the full bisection and the recovery path
# for entries that do trip this.
#
# Usage: check-roster-name-lengths.sh ROSTER_FILE
# Exit 0 and silent if every hf.co/-shaped entry's name segment is <= 80
# chars. Exit 1 and print one OVER(<len>) line per offender otherwise.
set -u

roster="${1:?usage: check-roster-name-lengths.sh ROSTER_FILE}"
[[ -f "$roster" ]] || { echo "FATAL: roster file not found: $roster" >&2; exit 1; }

over=0
while read -r t; do
  case "$t" in
    hf.co/*)
      n="${t#hf.co/*/}"
      n="${n%:*}"
      if [ "${#n}" -gt 80 ]; then
        echo "OVER(${#n}) $t"
        over=$((over + 1))
      fi
      ;;
  esac
done < <(awk 'NF && $0!~/^#/' "$roster")

if [ "$over" -gt 0 ]; then
  echo "FATAL: $over roster entr$([ $over -eq 1 ] && echo y || echo ies) exceed Ollama's 80-char hf.co name-segment limit (#2738) -- recover them under a local alias first (recover-oversized-models.sh), then point the roster at the alias." >&2
  exit 1
fi
exit 0
