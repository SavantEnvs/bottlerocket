#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# EDIT: RUN the test runner that mayhem/build.sh produced, then map its output to counts.
#   ctest:        (cd build-tests && ctest) ; parse "<P> tests passed, <F> failed out of <T>"
#   gtest binary: ./build-tests/<prog> ; parse "[==========] N ... ran." / "[  PASSED  ] P" / "[ SKIPPED ] S"
#   make/minunit: ./out/<runner> ; parse its pass/fail/total
# Do NOT compile here — if the runner is absent, fail (build.sh should have produced it).

# Bottlerocket's upstream Rust test suite lives in the sources/ workspace
# (unit + doc tests for datastore, models, migration-helpers, bottlerocket-release,
# constants, retry-read, settings-defaults/*, settings-migrations/*, ...).
# The root workspace members (packages/*, variants/*) are image-build stubs whose
# build.rs invokes buildsys (full OS image builds) — they carry no unit tests and
# are skipped. build.sh already compiled the suite (cargo test --no-run, normal
# flags); this only runs it, offline.
LOG=/tmp/cargo-test.log
env -u RUSTFLAGS cargo test --offline --manifest-path sources/Cargo.toml --workspace 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}

read -r P F S < <(awk '/^test result:/ {p+=$4; f+=$6; s+=$8} END {print p+0, f+0, s+0}' "$LOG")
echo "cargo test summary: passed=$P failed=$F ignored=$S (exit=$rc)"

if ! grep -q '^test result:' "$LOG"; then
  echo "ERROR: no 'test result:' lines found — suite did not run (build.sh should have prebuilt it)" >&2
  emit_ctrf "cargo-test" 0 1 0
  exit 1
fi
if [ "$rc" -ne 0 ] && [ "$F" -eq 0 ]; then
  echo "ERROR: cargo test exited $rc without reporting failures (harness error)" >&2
  emit_ctrf "cargo-test" "$P" 1 "$S"
  exit 1
fi

emit_ctrf "cargo-test" "$P" "$F" "$S"
