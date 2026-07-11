#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's cargo-fuzz target(s) as sanitized libFuzzer
# binaries (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS), plus the crates'
# own known-answer test suites (clean, non-sanitized) for mayhem/test.sh to RUN.
#
# Runs inside the commit image (RUST mayhem/Dockerfile) as `mayhem` in /mayhem.
# The Rust toolchain + cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo
# (pinned by the Dockerfile ENV — absolute, $HOME-independent).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry under $CARGO_HOME.
#   - The PATCH re-run resolves crates from that cache. The rlenv runtime exports
#     CARGO_NET_OFFLINE=true for the re-run so cargo won't try to refresh the
#     crates.io index over the (absent) network — so do NOT hard-code `--offline`.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# OSS-Fuzz Rust libFuzzer+ASan flags. cargo-fuzz sets the ASan flag itself, but we
# pin it explicitly. --cfg fuzzing matches libfuzzer-sys; force-frame-pointers aids
# ASan backtraces. -Zdwarf-version=3 forces DWARF < 4 (§6.2 item 10) — this nightly's
# plain -Cdebuginfo emits DWARF-5, which Mayhem's triage can't read. -Zdwarf-version
# is the reliable nightly knob for code rustc COMPILES (our crates + build-std).
# $RUST_DEBUG_FLAGS (the PATCH tier's debuginfo knob) is threaded through last so it
# wins — the base default is empty.
# Honor $SANITIZER_FLAGS being present in the environment (base contract); for Rust the
# instrumentation is -Zsanitizer=address (rustc ignores clang's $SANITIZER_FLAGS).
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing -Zsanitizer=address -Cdebuginfo=1 -Zdwarf-version=3 -Cforce-frame-pointers ${RUST_DEBUG_FLAGS:-}"
echo "SANITIZER_FLAGS (base, informational) = ${SANITIZER_FLAGS:-<unset>}"

# libfuzzer-sys compiles its bundled libFuzzer C++ runtime via the `cc` crate (clang),
# which defaults to DWARF-5; the `cc` crate honors CFLAGS/CXXFLAGS, so force DWARF 3
# there too so those C++ CUs are < 4 as well.
export CFLAGS="${CFLAGS:-} -gdwarf-3"
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-3"

# Additive cargo-fuzz crate (libfuzzer-sys 0.4) — upstream's own fuzz/ is honggfuzz.
FUZZ_DIR="mayhem/fuzz"
TRIPLE="x86_64-unknown-linux-gnu"

# DWARF<4 contract (§6.2 item 10): -Zsanitizer=address statically links the toolchain's
# PREBUILT ASan runtime (compiler-rt), whose objects carry DWARF 5 — and -Zdwarf-version
# only controls code rustc COMPILES, not that prebuilt archive. Those v5 CUs land FIRST
# in the linked binary and fail the DWARF<4 check (which reads the first CU). The runtime's
# debug info is useless for Mayhem triage, so strip it from the archive once (idempotent —
# re-stripping is a no-op, safe for the offline build.sh re-run). The binary then carries
# only our DWARF-3 CUs (Rust code + build-std) and still has .debug_info.
ASAN_A="$(rustc --print sysroot)/lib/rustlib/${TRIPLE}/lib/librustc-nightly_rt.asan.a"
if [ -f "$ASAN_A" ]; then
  echo "stripping debug info from prebuilt ASan runtime: $ASAN_A"
  objcopy --strip-debug "$ASAN_A" 2>/dev/null || objcopy --remove-section '.debug_*' "$ASAN_A" 2>/dev/null || true
fi

# Discover every target from the crate's fuzz_targets/ dir (one binary per target).
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }

echo "=== cargo fuzz build (image nightly, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

# Output dir for the built fuzz binaries. NOTE: the target NAMES (rabbit/hc-256/
# salsa20) collide with the upstream crate DIRECTORIES at /mayhem/<name>, so we
# cannot drop the binary at /mayhem/<name> (cp would land it INSIDE the crate dir).
# Use a dedicated /mayhem/bin/ and point the Mayhemfiles there.
OUT_DIR="/mayhem/bin"
mkdir -p "$OUT_DIR"

# Use the image's DEFAULT toolchain (the Dockerfile pinned it).
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "$OUT_DIR/$t"
  echo "built $OUT_DIR/$t"
done

# ── Build the crates' OWN test suites (RFC/eCRYPT known-answer tests) ──────────
# Clean, NON-sanitized build with the project's normal flags, in a SEPARATE target
# dir so it never collides with the cargo-fuzz tree. mayhem/test.sh only RUNS these.
echo "=== cargo test --no-run (KAT suites: rabbit, hc-256, salsa20) ==="
env -u RUSTFLAGS CARGO_TARGET_DIR="$SRC/mayhem/test-target" \
  cargo test --no-run -j "$MAYHEM_JOBS" -p rabbit -p hc-256 -p salsa20

echo "build.sh complete"
