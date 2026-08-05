#!/usr/bin/env bash
# probe-real-session-run.sh -- stage 2 of the real-data qualitative check.
#
# Takes stage 1's output (probe-real-session.py, run inside hp-llm-worker
# where Elasticsearch and contracts.py are reachable) and sends each real
# session's prompt to a live Ollama server, printing the raw reply for a
# human or agent to read and judge for groundedness -- not an automated
# score, see probe-real-session.py's module docstring for why.
#
# Usage:
#   probe-real-session-run.sh <stage1-output.json> <model-tag> [base-url]
#
# base-url defaults to http://127.0.0.1:11434 (the analysis host itself).

set -euo pipefail

input="${1:?usage: $0 <stage1-output.json> <model-tag> [base-url]}"
model="${2:?usage: $0 <stage1-output.json> <model-tag> [base-url]}"
base_url="${3:-http://127.0.0.1:11434}"

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

count=$(jq '.prompts | length' "$input")
if [ "$count" -eq 0 ]; then
  jq -r '.warning // "no prompts in stage 1 output"' "$input" >&2
  exit 0
fi

for i in $(seq 0 $((count - 1))); do
  session_id=$(jq -r ".prompts[$i].session_id" "$input")
  real_count=$(jq -r ".prompts[$i].real_command_count" "$input")
  truncated=$(jq -r ".prompts[$i].transcript_truncated" "$input")
  echo "== session $session_id ($real_count real commands, truncated=$truncated) ==" >&2

  jq -n \
    --arg model "$model" \
    --slurpfile stage1 "$input" \
    --argjson idx "$i" \
    '{
      model: $model,
      messages: [
        {role: "system", content: $stage1[0].prompts[$idx].system_prompt},
        {role: "user", content: $stage1[0].prompts[$idx].user_prompt}
      ],
      stream: false,
      think: false,
      options: {temperature: 0, seed: 144}
    }' \
  | curl -s "$base_url/api/chat" -d @- \
  | jq -r '.message.content // .response // .'

  echo >&2
done
