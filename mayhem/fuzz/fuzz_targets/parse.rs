#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = parse_datetime::parse_datetime(data);
    let _ = parse_datetime::parse_offset(data);
});
