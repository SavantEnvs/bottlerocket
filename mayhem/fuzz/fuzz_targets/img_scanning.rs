#![no_main]
use gptman::GPT;
use hex_literal::hex;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::sync::LazyLock;

// From bottlerocket-core-kit sources/updater/signpost/src/guid.rs
const fn uuid_to_guid(uuid: [u8; 16]) -> [u8; 16] {
    [
        uuid[3], uuid[2], uuid[1], uuid[0], uuid[5], uuid[4], uuid[7], uuid[6], uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
    ]
}

// From bottlerocket-core-kit sources/ghostdog/src/main.rs
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

// ghostdog::find_device_type, inlined (ghostdog is binary-only in core-kit)
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

fuzz_target!(|data: &[u8]| {
    // Prevent known panic in gptman-1.0.0 with inputs smaller than a sector size
    if data.len() < 512 {
        return;
    }

    let mut data = std::io::Cursor::new(data);
    let _ = find_device_type(&mut data);
});
