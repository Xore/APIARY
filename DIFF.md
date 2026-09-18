# #3023 cold-slot sweep patch

```diff
diff --git a/analysis/ghidra/benchmarks/corpus/sweep_extra.sh b/analysis/ghidra/benchmarks/corpus/sweep_extra.sh
index 010d1327..fdc75102 100755
--- a/analysis/ghidra/benchmarks/corpus/sweep_extra.sh
+++ b/analysis/ghidra/benchmarks/corpus/sweep_extra.sh
@@ -18,8 +18,9 @@
 # Only tags this script pulled are ever removed. Pre-existing roster models are
 # never touched.
 #
-# Same cold-slot protocol as the main sweep: `ollama stop` before every run,
-# sequential, N=2 with escalation to N=3 on disagreement, retry with backoff.
+# Same cold-slot protocol as the main sweep: isolate the workers and `ollama
+# stop` before every run, sequential, N=2 with escalation to N=3 on
+# disagreement, retry with backoff.
 #
 # #2728: `ollama pull` fetches a small (~480B) ollama-compat config blob that
 # HuggingFace generates on demand; for some repos that takes longer than
@@ -78,25 +79,48 @@ fi
 mkdir -p "$BASE/logs"
 cd "$REPO" || exit 1

-STOPPED_WORKERS=""
+WORKER_STATE_FILE=""
 restore_workers() {
-  [ -n "$STOPPED_WORKERS" ] || return 0
-  for c in $STOPPED_WORKERS; do
-    docker start "$c" >/dev/null 2>&1 \
-      && echo "$(date -u +%H:%M:%S) restored $c" \
-      || echo "$(date -u +%H:%M:%S) WARN could not restart $c -- do it by hand"
-  done
-  STOPPED_WORKERS=""
+  [ -n "$WORKER_STATE_FILE" ] || return 0
+  local c was_running running failed=0
+  while IFS=$'\t' read -r c was_running; do
+    [ "$was_running" = true ] || continue
+    running=$(docker inspect -f '{{.State.Running}}' "$c") || { failed=1; continue; }
+    [ "$running" = true ] && continue
+    if docker start "$c" >/dev/null 2>&1; then
+      echo "$(date -u +%H:%M:%S) restored $c"
+    else
+      echo "$(date -u +%H:%M:%S) WARN could not restart $c -- do it by hand"
+      failed=1
+    fi
+  done < "$WORKER_STATE_FILE"
+  if [ "$failed" -eq 0 ]; then
+    rm -f "$WORKER_STATE_FILE"
+  else
+    echo "$(date -u +%H:%M:%S) WARN original worker states retained in $WORKER_STATE_FILE"
+  fi
+}
+stop_running_workers() {
+  [ "$STOP_WORKERS" = "1" ] || return 0
+  local c running
+  while IFS=$'\t' read -r c _; do
+    running=$(docker inspect -f '{{.State.Running}}' "$c") || return 1
+    if [ "$running" = true ]; then
+      docker stop "$c" >/dev/null || return 1
+      echo "$(date -u +%FT%TZ) cold protocol: stopped $c"
+    fi
+  done < "$WORKER_STATE_FILE"
 }
 if [ "$STOP_WORKERS" = "1" ]; then
+  WORKER_STATE_FILE=$(mktemp "${TMPDIR:-/tmp}/sweep-extra-workers.XXXXXXXX") || exit 1
+  trap 'restore_workers' EXIT
+  trap 'exit 130' INT
+  trap 'exit 143' TERM
   for c in $LIVE_WORKERS; do
-    if docker ps --format '{{.Names}}' | grep -qx "$c"; then
-      docker stop "$c" >/dev/null 2>&1 && STOPPED_WORKERS="$STOPPED_WORKERS $c" \
-        && echo "$(date -u +%FT%TZ) cold protocol: stopped $c"
-    fi
+    running=$(docker inspect -f '{{.State.Running}}' "$c") || exit 1
+    printf '%s\t%s\n' "$c" "$running" >> "$WORKER_STATE_FILE"
   done
-  # EXIT alone is not enough: this script is routinely killed between models.
-  trap 'restore_workers' EXIT INT TERM
+  stop_running_workers || exit 1
 fi

 score_of() { python3 -c "import json;print(json.load(open('$1'))['total_score'])" 2>/dev/null; }
@@ -160,6 +184,8 @@ do_run() { # tier slug tag n
   local extra=""; [ "$tier" = "B" ] && extra="--ghidra-cache $GHIDRA_CACHE"
   local try=1
   while [ $try -le $MAXTRY ]; do
+    # Re-isolate before every attempt, even if a worker was restarted mid-sweep.
+    stop_running_workers || { echo "cold protocol: worker stop failed" >&2; exit 1; }
     docker exec ghidra-ollama-1 ollama stop "$tag" >/dev/null 2>&1
     sleep 5
     echo "$(date -u +%H:%M:%S) start $tier $slug run$n try$try"
```

1. The header now states both parts of #3023's cold-slot protocol: worker isolation and `ollama stop` per run.
2. A unique temporary inventory captures both workers' original running/stopped states before any stop; an already-stopped `hp-llm-worker` is never started.
3. The stop helper checks actual state before stopping, repeats before every benchmark attempt, and aborts instead of benchmarking with competing GPU users.
4. EXIT restoration starts only workers originally running; INT/TERM exit through that trap, and failed restoration retains the inventory for manual recovery.
5. Existing `STOP_WORKERS`/`LIVE_WORKERS` caller controls are preserved; `coldrun.sh`, `round7_sweep.sh`, and `requant_sweep.sh` invoke the same driver without incompatible assumptions.

Validation: `bash -n` and `git diff --check` pass. Shellcheck's three existing findings (SC2086 at `MAXTRY` and intentional `$extra` splitting, SC2034 at the retry counter) remain outside this narrow fix; shellcheck passes when those existing codes are excluded. No sweep was executed and neither worker's live state was changed.
