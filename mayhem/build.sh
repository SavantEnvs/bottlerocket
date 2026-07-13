#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's cargo-fuzz target(s) as sanitized libFuzzer
# binaries (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS). EDIT per repo.
#
# Runs inside the commit image (RUST mayhem/Dockerfile) as `mayhem` in /mayhem.
# The Rust toolchain + cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo
# (pinned by the Dockerfile ENV — absolute, $HOME-independent).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry under $CARGO_HOME.
#   - The PATCH re-run resolves crates from that cache. The rlenv runtime exports
#     CARGO_NET_OFFLINE=true for the re-run so cargo won't try to refresh the
#     crates.io index over the (absent) network — so do NOT hard-code `--offline`
#     here (it would break this first, online build).
#   - For a FULLY self-contained image (no runtime flag needed) instead vendor:
#       cargo vendor --versioned-dirs vendor   # commit vendor/ + a .cargo/config.toml
#     with [source.crates-io] replace-with = "vendored-sources".
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# Sanitizer note: cargo-fuzz drives Rust instrumentation through RUSTFLAGS
# `-Zsanitizer=address` (the OSS-Fuzz FUZZING_LANGUAGE=rust path), NOT clang's
# $SANITIZER_FLAGS / $CFLAGS — those don't apply to rustc, so the fuzzed code is
# sanitized via RUSTFLAGS below, not $SANITIZER_FLAGS.
#
# Debug-info contract (SPEC §6.2 item 10): thread $RUST_DEBUG_FLAGS so the fuzz
# binaries carry DWARF < 4 symbols via rustc (-Zdwarf-version=3, nightly); the
# base image may override RUST_DEBUG_FLAGS.
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -Zdwarf-version=3}"
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing -Zsanitizer=address $RUST_DEBUG_FLAGS"
# libfuzzer-sys compiles a bundled libFuzzer via the cc crate (clang -> DWARF-5 by
# default); force DWARF-3 on those C/C++ objects too, so NO compilation unit in the
# linked binary is >= 4 (the prebuilt std/asan archives are debug-stripped in the
# Dockerfile).
export CFLAGS="${CFLAGS:-} -gdwarf-3"
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-3"

# EDIT: the cargo-fuzz crate directory. Use upstream's own fuzz/ when it builds on
# the pinned nightly; otherwise add an ADDITIVE mayhem/fuzz/ crate (leaves upstream
# untouched) and point --fuzz-dir at it.
FUZZ_DIR="mayhem/fuzz"
TRIPLE="x86_64-unknown-linux-gnu"

# Discover every target from the crate's fuzz_targets/ dir (one binary per target).
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }

echo "=== cargo fuzz build (image nightly, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

# Use the image's DEFAULT toolchain (the Dockerfile pinned it). A `+toolchain`
# override would make rustup try to install another channel into the locked /opt/rust.
# Force a clean relink so no stale DWARF-5 object lingers from a prior cache.
rm -rf "$SRC/$FUZZ_DIR/target"
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"     # EDIT the output path/name to match your Mayhemfile target:
  echo "built /mayhem/$t"
done

# Build the project's TEST suite too — with the project's NORMAL flags (a clean,
# non-sanitized build) — so mayhem/test.sh only RUNS it. Bottlerocket's Rust test
# suite is the sources/ workspace; the root workspace (packages/, variants/) holds
# buildsys image-build stubs with no unit tests.
echo "=== prebuilding upstream test suite (sources/ workspace, normal flags) ==="
env -u RUSTFLAGS cargo test --no-run --manifest-path sources/Cargo.toml --workspace

echo "build.sh complete"
