#!/usr/bin/env bash
#
# mayhem/build.sh — Bottlerocket Mayhem integration build (Rust / cargo-fuzz).
#
# Runs inside the commit image (RUST mayhem/Dockerfile) as `mayhem` in /mayhem. The Rust
# toolchain + cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo (pinned by the
# Dockerfile ENV — absolute, $HOME-independent). Produces:
#   1. /mayhem/bottlerocket-kat   CLEAN, dynamically linked known-answer probe (mayhem/kat)
#                                 that mayhem/test.sh runs as the behavioral oracle.
#   2. the upstream sources/ workspace test suite, precompiled with NORMAL flags
#                                 (cargo test --no-run) so mayhem/test.sh only RUNS it.
#   3. /mayhem/parse, /mayhem/img_scanning
#                                 sanitized libFuzzer targets from the ADDITIVE mayhem/fuzz
#                                 cargo-fuzz crate (ASan via RUSTFLAGS, DWARF-3, LSan hook).
#
# TARGETS (what is fuzzed, and why the crate is pulled from core-kit)
#   parse         parse-datetime::{parse_datetime, parse_offset} — the Bottlerocket crate
#                 that parses `--time`-style arguments (RFC 3339 or "in 7 days"). The crate
#                 moved out of this repo into bottlerocket-os/bottlerocket-core-kit; the fuzz
#                 crate pins it by git rev so the historical target keeps fuzzing the same code.
#   img_scanning  ghostdog's find_device_type() — the GPT partition-table scan that classifies
#                 a block device as "system" vs "ephemeral" — over gptman 1.x, the version
#                 core-kit pins. ghostdog is binary-only, so the function is inlined verbatim.
#                 History: three cloud runs ended at 0 edges. Cause: gptman 1.1.4's
#                 GPT::read_from computes `len / sector_size - 1` for the backup-header seek,
#                 which underflows for an image shorter than one sector, and GPT::find_from
#                 retries at sector size 4096 after 512 — so EVERY input of 512..4095 bytes
#                 (i.e. everything libFuzzer tries first) panicked under the fuzz build's
#                 overflow checks before any GPT code ran. The harness now zero-pads images to
#                 one 4096-byte sector (a real block device is never shorter); the reproducer
#                 and upstream fix live in
#                 mayhem/img-scanning/known-findings/gptman-short-image-seek-underflow/.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry + git db under $CARGO_HOME.
#   - mayhem/fuzz and mayhem/kat commit their Cargo.lock; sources/ ships upstream's. Every
#     dependency is therefore pinned and resolves from the in-image cache on the re-run (the
#     rlenv runtime exports CARGO_NET_OFFLINE=true) — so do NOT hard-code `--offline` here.
#   - Re-running on the built tree is incremental (cargo fingerprints RUSTFLAGS/profile).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

# The toolchain the Dockerfile installed (exported as ENV RUST_CHANNEL). Named EXPLICITLY on
# every cargo invocation so no rust-toolchain file can hijack the channel; already installed,
# so rustup never touches the network. Fallback: whatever rustup has active.
RUST_CHANNEL="${RUST_CHANNEL:-$(rustup show active-toolchain | awk '{print $1}')}"
[ -n "$RUST_CHANNEL" ] || { echo "ERROR: cannot determine the Rust toolchain (RUST_CHANNEL unset)" >&2; exit 1; }

cd "$SRC"
TRIPLE="x86_64-unknown-linux-gnu"

# ── 1. KAT probe (the behavioral oracle) — CLEAN build: no sanitizer, no fuzzing cfg ──────
# A normal dynamically-linked Rust binary over the same two code paths the fuzz targets
# cover (parse-datetime, ghostdog's GPT scan). test.sh asserts its exact output lines; the
# gate's LD_PRELOAD sabotage shim neuters it (empty output => the oracle FAILS).
echo "=== building KAT probe (clean, dynamically linked) ==="
env -u RUSTFLAGS -u CFLAGS -u CXXFLAGS \
  cargo +"$RUST_CHANNEL" build --release --manifest-path mayhem/kat/Cargo.toml
KAT_BIN="$SRC/mayhem/kat/target/release/bottlerocket-kat"
[ -x "$KAT_BIN" ] || { echo "ERROR: KAT probe not built at $KAT_BIN" >&2; exit 1; }
cp "$KAT_BIN" /mayhem/bottlerocket-kat
# Regression guard: the oracle only works if the probe is dynamically linked (so the
# sabotage shim can neuter it). A static binary would silently defeat the check.
if ! file /mayhem/bottlerocket-kat | grep -q 'dynamically linked'; then
  echo "ERROR: KAT probe is not dynamically linked — the sabotage oracle would be defeated" >&2
  file /mayhem/bottlerocket-kat >&2
  exit 1
fi
echo "built /mayhem/bottlerocket-kat (dynamically linked)"

# ── 2. Upstream test suite, NORMAL flags (clean build) — test.sh only RUNS it ─────────────
# Bottlerocket's Rust unit tests live in the sources/ workspace (datastore, models,
# migration-helpers, retry-read, settings-migrations, ...). The ROOT workspace
# (packages/, variants/) holds buildsys image-build stubs with no unit tests and is NOT
# built (that is the OS image build). sources/Cargo.lock is committed upstream.
echo "=== prebuilding upstream test suite (sources/ workspace, normal flags) ==="
env -u RUSTFLAGS -u CFLAGS -u CXXFLAGS \
  cargo +"$RUST_CHANNEL" test --no-run --manifest-path sources/Cargo.toml --workspace

# ── 3. Sanitized libFuzzer targets via cargo-fuzz ─────────────────────────────────────────
# Sanitizers (§6.1): the base provides clang $SANITIZER_FLAGS (ASan+UBSan, halting). rustc
# cannot consume those clang flags, but we honor the KNOB: a non-empty $SANITIZER_FLAGS =>
# instrument the Rust build with ASan (the OSS-Fuzz Rust path, -Zsanitizer=address); an
# explicit empty `--build-arg SANITIZER_FLAGS=` yields an un-sanitized build.
RUST_SAN=""
if [ -n "${SANITIZER_FLAGS:-}" ]; then
  # LSan hook (BUILD time only, SPEC §6.2 item 15): -Zsanitizer=address bundles LeakSanitizer;
  # link a strong __lsan_is_turned_off() (mayhem/lsan_off.cc) into every fuzz binary so only
  # leak detection is off — ASan/UBSan stay on. Compiled with the base clang++ (DWARF-3,
  # PIE) into the gitignored fuzz target dir and handed to rustc's final link via
  # -Clink-arg. Idempotent: recompiled on every re-run.
  LSAN_OFF_OBJ="$SRC/mayhem/fuzz/target/lsan_off.o"
  install -d "$(dirname "$LSAN_OFF_OBJ")"
  "${CXX:-clang++}" -c -O2 -fPIE -gdwarf-3 mayhem/lsan_off.cc -o "$LSAN_OFF_OBJ"
  # (grep WITHOUT -q: under `pipefail`, -q exits at the first match and nm dies of SIGPIPE.)
  nm "$LSAN_OFF_OBJ" | grep ' T __lsan_is_turned_off$' >/dev/null \
    || { echo "ERROR: $LSAN_OFF_OBJ lacks a strong __lsan_is_turned_off" >&2; exit 1; }
  RUST_SAN="-Zsanitizer=address -Clink-arg=$LSAN_OFF_OBJ"
fi

# Debug-info contract (SPEC §6.2 item 10): every fuzz binary must carry DWARF < 4. rustc
# nightly defaults to DWARF-5, so $RUST_DEBUG_FLAGS pins -Zdwarf-version=3 (the base may
# override RUST_DEBUG_FLAGS). libfuzzer-sys compiles the bundled libFuzzer via the cc crate
# (clang => DWARF-5 by default): force DWARF-3 on those C/C++ objects too. The prebuilt
# std/ASan-runtime archives are debug-stripped in the Dockerfile, so NO compilation unit in
# the linked binary is >= 4.
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -Zdwarf-version=3}"
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing ${RUST_SAN} ${RUST_DEBUG_FLAGS}"
export CFLAGS="${CFLAGS:-} -gdwarf-3"
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-3"

# The ADDITIVE fuzz crate: its own [workspace], so cargo-fuzz writes binaries under
# mayhem/fuzz/target/ (NOT the repo-root target/). One binary per fuzz_targets/*.rs.
FUZZ_DIR="mayhem/fuzz"
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }

echo "=== cargo fuzz build (pinned nightly $RUST_CHANNEL, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo +"$RUST_CHANNEL" fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"     # Mayhemfile cmd: /mayhem/<t>
  if [ -n "$RUST_SAN" ]; then
    # Regression guard: the LSan hook must be a STRONG symbol in the final binary (the
    # runtime's own weak default would otherwise silently leave leak detection ON).
    nm "/mayhem/$t" | grep ' T __lsan_is_turned_off$' >/dev/null \
      || { echo "ERROR: /mayhem/$t does not carry the strong __lsan_is_turned_off hook" >&2; exit 1; }
  fi
  echo "built /mayhem/$t"
done

echo "build.sh complete"
