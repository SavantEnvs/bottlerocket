# gptman: backup-header seek underflows on an image shorter than one sector

**Target:** `img-scanning` (ghostdog `find_device_type()` over gptman 1.1.4, the version
bottlerocket-core-kit pins). **Mayhem:** defect #3383747 (improper-input-validation, CWE-20),
5 crash reports, present in all three cloud runs (2026-08-24, 08-30, 09-06) — each at 0 edges.

**Reproducer:** `short-image-1024-bytes.bin` (1024 x `A`). Two input bands reach the
faulting expression through `GPT::find_from`:

* `len < 512` — the 512-byte-sector pass itself: the primary read hits EOF, and the
  backup-header fallback computes `len / 512 - 1` = `0 - 1`.
* `604 <= len < 4096` — long enough that the 512-pass primary AND backup header
  reads both succeed and both fail with `InvalidSignature` (any non-`EFI PART` bytes), so
  `find_from` retries at sector size 4096, where the primary read hits EOF and the fallback
  computes `len / 4096 - 1` = `0 - 1`. This is the band every early libFuzzer input lands
  in, and the one the original harness's `data.len() < 512` guard did not cover.

Direct reproduction against the crate (no harness involved):

```rust
// gptman = "=1.1.4"; dev profile (overflow checks on)
let n: usize = 1024;                       // or 100, 4095 — but NOT 600 (EOF, no retry) or 4096
let mut r = std::io::Cursor::new(vec![0x41u8; n]);
let _ = gptman::GPT::find_from(&mut r);
// thread 'main' panicked at .../gptman-1.1.4/src/lib.rs:727:41:
// attempt to subtract with overflow
```

In a release build the subtraction wraps and the same call returns
`Err(ReadError(Deserialize(Io(UnexpectedEof)), InvalidSignature))`.

## Cause

`gptman-1.1.4/src/lib.rs:727`, `GPT::read_from`, backup-header fallback:

```rust
let header = GPTHeader::read_from(&mut reader).or_else(|primary_err| {
    let len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start((len / sector_size - 1) * sector_size))?;   // <-- here
    ...
```

When `len < sector_size`, `len / sector_size == 0` and `0u64 - 1` underflows: a panic
(`attempt to subtract with overflow`) under overflow checks, a wrapped seek to
`(u64::MAX) * sector_size` (which then fails to read) in a release build. `GPT::find_from`
tries sector size 512 and then 4096, so every image shorter than 4096 bytes reaches the
faulting expression on the 4096 pass even when the 512 pass was fine — that is why the
original harness's `data.len() < 512` guard did not help, and why libFuzzer (whose early
inputs are all short) crashed on essentially every input it grew past ~600 bytes: 58M
executions per 20-minute run, a corpus stuck at 5 entries, `edges_covered = 0`.

## Impact

* Fuzz harness / any debug-built consumer: deterministic panic (abort) on sub-4096-byte
  images (the bands above). Not a memory-safety issue.
* Production ghostdog: unreachable — it scans real block devices (always >> one sector),
  and in release the arithmetic wraps into a read error, which `find_device_type` maps to
  `"ephemeral"`.
* Severity: low (robustness bug in an upstream dependency).

## Fix (one line, upstream gptman)

Guard the fallback before seeking — as gptman >= 2.0 already does in `GPT::read_from`:

```rust
if len < sector_size { return Err(primary_err); }
```

or bump core-kit's `gptman` pin to a release that contains the check.

## Harness mitigation

`mayhem/fuzz/fuzz_targets/img_scanning.rs` zero-pads inputs shorter than 4096 bytes up to
one 4096-byte sector (a real block device is never shorter), so the fuzzer keeps exploring
header parsing with short inputs instead of dying in the dependency's fallback. The
reproducer lives here, never under `testsuite/` (seeds are replayed on every run).
