# parse-datetime: `now + offset` panics for a large-but-valid count

**Target:** `parse` (`parse_datetime::parse_datetime`, bottlerocket-core-kit
`sources/parse-datetime/src/lib.rs`). **Mayhem:** defect #3356067
(improper-input-validation, CWE-20), 5 crash reports, present in every cloud run.

**Reproducer:** `in-4294967295-weeks.txt` — the string `in 4294967295 weeks`
(`u32::MAX` weeks). Any count that pushes "now" past chrono's maximum representable
date (year 262143 — roughly >= 13.6 million weeks, >= 95 million days, or
>= 2.3 billion hours) reproduces:

```
$ /mayhem/parse -runs=1 mayhem/parse/known-findings/datetime-add-overflow/in-4294967295-weeks.txt
thread '<unnamed>' panicked at .../bottlerocket-core-kit-.../sources/parse-datetime/src/lib.rs:63:16:
`DateTime + TimeDelta` overflowed
SUMMARY: libFuzzer: deadly signal
```

(chrono's `Add` impl is `#[track_caller]`, so the panic is attributed to parse-datetime's
`now + offset` line. Fork-mode fuzzing from the seeds reproduces it within seconds with
inputs such as `0000001000000000 weeks`.)

## Cause

```rust
pub fn parse_datetime(input: &str) -> Result<DateTime<Utc>> {
    ...
    let offset = parse_offset(input)?;   // count validated only as u32; try_weeks(i64) succeeds
    let now = Utc::now();
    let then = now + offset;             // <-- chrono's Add impl: checked_add_signed(..).expect(..)
    Ok(then)
}
```

`parse_offset` accepts any `u32` count, and `TimeDelta::try_weeks(i64::from(count))`
succeeds (the delta itself fits), but adding it to `now` leaves chrono's representable
`NaiveDate` range, and chrono's `Add<TimeDelta> for DateTime` panics rather than returning
an error.

## Impact

Panic (process abort) in whichever Bottlerocket tool hands a user-supplied string to
`parse_datetime` (the `--time`/"in N units" style arguments). Denial of service of the
calling process on a crafted argument; no memory unsafety. Severity: low.

## Fix (one line)

```rust
let then = now.checked_add_signed(offset).context(error::DateArgInvalidSnafu {
    input,
    msg: "date argument is too far in the future",
})?;
```

(or clamp the accepted count). This is a genuine finding in Bottlerocket code and is
deliberately NOT masked in the harness; the reproducer lives here, never under
`testsuite/`.
