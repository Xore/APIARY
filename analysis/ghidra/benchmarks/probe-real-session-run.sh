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

# Stage 1 builds the transcript from up to MAX_CONTENT_CHARS (default 12000)
# chars of captured commands, plus the system/user prompt scaffolding around
# it. Without an explicit num_ctx, the request falls back to whatever the
# target Ollama server happens to be configured with -- 2048 on a default
# install -- which silently drops the head of the evidence (system prompt
# and earliest commands) before generation (#2059). 8192 covers ~12000
# chars of transcript (~3000 tokens at ~4 chars/token) plus scaffolding with
# headroom left for the response; override for a larger MAX_CONTENT_CHARS.
num_ctx="${PROBE_REAL_SESSION_NUM_CTX:-8192}"

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

  response=$(jq -n \
    --arg model "$model" \
    --slurpfile stage1 "$input" \
    --argjson idx "$i" \
    --argjson num_ctx "$num_ctx" \
    '{
      model: $model,
      messages: [
        {role: "system", content: $stage1[0].prompts[$idx].system_prompt},
        {role: "user", content: $stage1[0].prompts[$idx].user_prompt}
      ],
      stream: false,
      think: false,
      options: {temperature: 0, seed: 144, num_ctx: $num_ctx}
    }' \
  | curl -s "$base_url/api/chat" -d @-)

  # Ollama drops the head of an over-length prompt and keeps generating
  # rather than raising an HTTP error, so a truncated transcript would
  # otherwise reach the human judge silently, indistinguishable from a
  # complete one. done=false or truncated=true is that signal -- fail loud
  # instead of handing over a partial result (#2059).
  ollama_done=$(jq -r '.done' <<<"$response")
  ollama_truncated=$(jq -r '.truncated' <<<"$response")
  if [ "$ollama_done" = "false" ] || [ "$ollama_truncated" = "true" ]; then
    echo "ERROR: session $session_id: Ollama signaled context truncation" \
         "(done=$ollama_done, truncated=$ollama_truncated) -- refusing to" \
         "hand a partial transcript to the judge. Raise num_ctx (currently" \
         "$num_ctx via PROBE_REAL_SESSION_NUM_CTX) or lower MAX_CONTENT_CHARS." >&2
    exit 1
  fi

  jq -r '.message.content // .response // .' <<<"$response"

  echo >&2
done
