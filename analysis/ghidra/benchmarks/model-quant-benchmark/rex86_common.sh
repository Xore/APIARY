# rex86_common.sh -- shared helpers for the rex86_*.sh / real_bench_run.sh
# GPU-batch drivers in this directory. Sourced, never executed directly.
#
# Single-GPU guard (#2055 item 3): three different idioms used to coexist
# for "wait until no other driver is using the GPU" -- a broad pgrep
# pattern (rex86_backfill_extra_quants.sh, rex86_run_all_base.sh) that
# still missed rex86_bench.sh/real_bench_run.sh/
# rex86_retry_failed_adapters.sh/rex86_run_deepseek_v2_full.sh entirely, a
# narrow 'bash .*name\.sh' pattern (the latter two) that only matched
# specific scripts by literal name and missed any invocation not prefixed
# "bash ", and no guard at all (rex86_backfill_direct.sh,
# rex86_backfill_resume.sh, rex86_bench.sh, real_bench_run.sh). One
# pattern, defined once, matches every current driver by construction
# (the shared rex86_/real_bench_run naming convention) instead of an
# enumerated list that has to be kept in sync by hand.
REX86_DRIVER_PATTERN='rex86_[A-Za-z0-9_]+\.sh|real_bench_run\.sh'

# Blocks until no OTHER process (self excluded by PID) is running a
# rex86_*.sh/real_bench_run.sh driver -- this host has exactly one GPU and
# every driver that launches llama-server/vllm/ollama must serialize
# behind whichever one is already using it.
rex86_wait_for_gpu_drivers() {
  while pgrep -f "$REX86_DRIVER_PATTERN" | grep -vx "$$" | grep -q .; do
    sleep 30
  done
}
