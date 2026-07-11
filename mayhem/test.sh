#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the crates' OWN known-answer test suites (RFC4503 for rabbit,
# the HC-256 spec vectors, and the eCRYPT/Salsa20 vectors), already compiled by
# mayhem/build.sh into mayhem/test-target. These are real behavioral oracles: each
# asserts the cipher's keystream/output against fixed published vectors, so a PATCH
# that neuters a cipher to a no-op (or exit(0)) FAILS here.
#
# Does NOT compile — build.sh already ran `cargo test --no-run` (clean flags) into
# the same CARGO_TARGET_DIR. Emits a CTRF summary and exits non-zero iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

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

# Run the pre-built test binaries via cargo (no recompile: build.sh already built them
# into this target dir with these flags). Capture libtest output for count parsing.
log="$(mktemp)"
env -u RUSTFLAGS CARGO_TARGET_DIR="$SRC/mayhem/test-target" \
  cargo test -j "$MAYHEM_JOBS" -p rabbit -p hc-256 -p salsa20 2>&1 | tee "$log"
run_rc=${PIPESTATUS[0]}

# libtest prints one "test result: <ok|FAILED>. P passed; F failed; I ignored; ..."
# line per test binary. Sum across all of them.
passed=$(grep -Eo '[0-9]+ passed' "$log" | awk '{s+=$1} END{print s+0}')
failed=$(grep -Eo '[0-9]+ failed' "$log" | awk '{s+=$1} END{print s+0}')
skipped=$(grep -Eo '[0-9]+ ignored' "$log" | awk '{s+=$1} END{print s+0}')
rm -f "$log"

# Safety net: if cargo itself failed (e.g. nothing ran) but parsing found no failures,
# force a failure so a broken run can't masquerade as green.
if [ "$run_rc" -ne 0 ] && [ "$failed" -eq 0 ]; then
  failed=1
fi
if [ "$(( passed + failed ))" -eq 0 ]; then
  echo "ERROR: no tests ran — build.sh should have compiled the KAT suites" >&2
  failed=1
fi

emit_ctrf "cargo-test" "$passed" "$failed" "$skipped"
