//! bottlerocket-kat — known-answer probe run by mayhem/test.sh (the behavioral oracle).
//!
//! Prints one `KATn ...` line per assertion; mayhem/test.sh compares every line against an
//! exact expected string. The expected values were derived INDEPENDENTLY of this code (epoch
//! seconds via Python's datetime; the GPT images via mayhem/img-scanning/mkseeds.py, a pure
//! Python generator), so a neutered / no-op / wrong program cannot reproduce them.
//!
//! It exercises exactly the two code paths the fuzz targets cover:
//!   * parse-datetime::{parse_datetime, parse_offset}   (fuzz target `parse`)
//!   * ghostdog's find_device_type() over gptman          (fuzz target `img-scanning`)
//!
//! Usage: bottlerocket-kat <dir with the img-scanning seed images>
use std::collections::HashSet;
use std::io::Cursor;
use std::sync::LazyLock;

use gptman::GPT;
use hex_literal::hex;

// From bottlerocket-core-kit sources/updater/signpost/src/guid.rs
const fn uuid_to_guid(uuid: [u8; 16]) -> [u8; 16] {
    [
        uuid[3], uuid[2], uuid[1], uuid[0], uuid[5], uuid[4], uuid[7], uuid[6], uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
    ]
}

// From bottlerocket-core-kit sources/ghostdog/src/main.rs (same table as the fuzz harness)
static SYSTEM_PARTITION_TYPES: LazyLock<HashSet<[u8; 16]>> = LazyLock::new(|| {
    [
        uuid_to_guid(hex!("c12a7328 f81f 11d2 ba4b 00a0c93ec93b")), // EFI_SYSTEM
        uuid_to_guid(hex!("6b636168 7420 6568 2070 6c616e657421")), // BOTTLEROCKET_BOOT
        uuid_to_guid(hex!("5526016a 1a97 4ea4 b39a b7c8c6ca4502")), // BOTTLEROCKET_ROOT
        uuid_to_guid(hex!("598f10af c955 4456 6a99 7720068a6cea")), // BOTTLEROCKET_HASH
        uuid_to_guid(hex!("0c5d99a5 d331 4147 baef 08e2b855bdc9")), // BOTTLEROCKET_RESERVED
        uuid_to_guid(hex!("440408bb eb0b 4328 a6e5 a29038fad706")), // BOTTLEROCKET_PRIVATE
        uuid_to_guid(hex!("626f7474 6c65 6474 6861 726d61726b73")), // BOTTLEROCKET_DATA
    ]
    .iter()
    .copied()
    .collect()
});

// ghostdog::find_device_type, inlined (ghostdog is binary-only in core-kit); identical to
// the copy in mayhem/fuzz/fuzz_targets/img_scanning.rs.
fn find_device_type<R>(reader: &mut R) -> String
where
    R: std::io::Read + std::io::Seek,
{
    let mut device_type = "ephemeral";
    if let Ok(gpt) = GPT::find_from(reader) {
        let system_device = gpt.iter().any(|(_, p)| {
            p.is_used()
                && (SYSTEM_PARTITION_TYPES.contains(&p.partition_type_guid)
                    || p.partition_name.as_str().starts_with("BOTTLEROCKET"))
        });
        if system_device {
            device_type = "system"
        }
    }
    device_type.to_string()
}

fn offset_secs(s: &str) -> String {
    match parse_datetime::parse_offset(s) {
        Ok(d) => d.num_seconds().to_string(),
        Err(_) => "err".to_string(),
    }
}

fn main() {
    let seed_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "mayhem/img-scanning/testsuite".to_string());

    // ── parse-datetime ─────────────────────────────────────────────────────────────────
    // KAT1: RFC 3339 absolute (UTC) -> epoch seconds.
    let dt = parse_datetime::parse_datetime("2021-01-01T00:00:00Z").expect("KAT1 rfc3339");
    println!("KAT1 rfc3339_utc_epoch={}", dt.timestamp());
    // KAT2: RFC 3339 with a +02:00 offset (leap day) -> normalized to UTC epoch seconds.
    let dt = parse_datetime::parse_datetime("2020-02-29T12:34:56+02:00").expect("KAT2 rfc3339");
    println!("KAT2 rfc3339_tz_epoch={}", dt.timestamp());
    // KAT3: fractional seconds + negative offset -> epoch seconds and exact nanoseconds.
    let dt = parse_datetime::parse_datetime("2023-06-15T08:30:00.123456789-07:00")
        .expect("KAT3 rfc3339");
    println!(
        "KAT3 rfc3339_frac_epoch={} nanos={}",
        dt.timestamp(),
        dt.timestamp_subsec_nanos()
    );
    // KAT4: relative shorthands -> exact offsets in seconds (optional "in" prefix, singular/plural).
    println!(
        "KAT4 offsets={},{},{},{},{}",
        offset_secs("in 1 hour"),
        offset_secs("7 days"),
        offset_secs("in 2 weeks"),
        offset_secs("0 hours"),
        offset_secs("in 500 weeks")
    );
    // KAT5: rejected inputs -> the crate's exact error text.
    match parse_datetime::parse_offset("in 1 month") {
        Ok(_) => println!("KAT5 unexpected_ok"),
        Err(e) => println!("KAT5 err={e}"),
    }
    match parse_datetime::parse_offset("99999999999 hours") {
        Ok(_) => println!("KAT6 unexpected_ok"),
        Err(e) => println!("KAT6 err={e}"),
    }
    println!(
        "KAT7 rejected={},{},{},{}",
        offset_secs("in"),
        offset_secs("0 hou"),
        offset_secs("at 3 days"),
        offset_secs("in 3 days ago")
    );

    // ── ghostdog GPT scan over gptman ──────────────────────────────────────────────────
    // KAT8: an all-zero 8 KiB disk (no GPT at either sector size) is ephemeral.
    let zeros = vec![0u8; 8192];
    println!("KAT8 zeros={}", find_device_type(&mut Cursor::new(&zeros)));
    // KAT9: each committed seed image -> the device type ghostdog assigns it.
    for name in [
        "gpt512-bottlerocket-root.img",
        "gpt512-bottlerocket-name.img",
        "gpt512-linux-data.img",
        "gpt512-efi-linux.img",
        "gpt4k-bottlerocket-root.img",
        "mbr-only-4k.img",
    ] {
        let path = format!("{seed_dir}/{name}");
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("KAT9 read {path}: {e}"));
        println!("KAT9 {name}={}", find_device_type(&mut Cursor::new(&data)));
    }
    // KAT10: parsed geometry of the 512-byte-sector Bottlerocket root image.
    let data = std::fs::read(format!("{seed_dir}/gpt512-bottlerocket-root.img")).expect("KAT10 read");
    let gpt = GPT::find_from(&mut Cursor::new(&data)).expect("KAT10 GPT::find_from");
    let used: Vec<u32> = gpt.iter().filter(|(_, p)| p.is_used()).map(|(i, _)| i).collect();
    println!(
        "KAT10 sector_size={} first_usable_lba={} last_usable_lba={} entries={} used={:?} name1={} name2={} range1={}..={}",
        gpt.sector_size,
        gpt.header.first_usable_lba,
        gpt.header.last_usable_lba,
        gpt.header.number_of_partition_entries,
        used,
        gpt[1].partition_name.as_str(),
        gpt[2].partition_name.as_str(),
        gpt[1].starting_lba,
        gpt[1].ending_lba
    );
    // KAT11: the 4096-byte-sector image is only found on GPT::find_from's 4096 retry.
    let data = std::fs::read(format!("{seed_dir}/gpt4k-bottlerocket-root.img")).expect("KAT11 read");
    let gpt = GPT::find_from(&mut Cursor::new(&data)).expect("KAT11 GPT::find_from");
    println!(
        "KAT11 sector_size={} backup_lba={} name1={}",
        gpt.sector_size, gpt.header.backup_lba, gpt[1].partition_name.as_str()
    );
}
