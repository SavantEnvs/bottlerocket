#!/usr/bin/env python3
"""Generate small, valid GPT disk images as libFuzzer seeds for the img-scanning target.

Layout (S = sector size, N = total sectors, 4 partition entries = 512 B = 1 sector at S=512):
  LBA 0        protective MBR (0xEE partition, 0x55AA signature)
  LBA 1        primary GPT header (92 B, CRC32 over header + entries array)
  LBA 2        partition entry array (4 x 128 B)
  LBA 3..N-3   usable
  LBA N-2      backup partition entry array
  LBA N-1      backup GPT header
Mirrors gptman's own GPTHeader::update_from() geometry (first_usable = 2 + array_sectors,
last_usable = N - array_sectors - 2, backup entries at last_usable + 1, backup header at N - 1).
"""
import struct, sys, zlib, uuid, os

def uuid_to_guid(u):  # same byte swizzle as signpost::uuid_to_guid (mixed-endian GUID)
    b = bytes.fromhex(u.replace(' ', '').replace('-', ''))
    return bytes([b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6]]) + b[8:16]

EFI_SYSTEM        = uuid_to_guid("c12a7328 f81f 11d2 ba4b 00a0c93ec93b")
BOTTLEROCKET_ROOT = uuid_to_guid("5526016a 1a97 4ea4 b39a b7c8c6ca4502")
BOTTLEROCKET_DATA = uuid_to_guid("626f7474 6c65 6474 6861 726d61726b73")
LINUX_FS          = uuid_to_guid("0fc63daf 8483 4772 8e79 3d69d8477de4")
ZERO_GUID         = bytes(16)

def entry(type_guid, name, start, end, uniq=b'\x11'*16, attrs=0):
    n = name.encode('utf-16-le')
    assert len(n) <= 72
    return type_guid + uniq + struct.pack('<QQQ', start, end, attrs) + n.ljust(72, b'\0')

def header(primary_lba, backup_lba, first_usable, last_usable, entry_lba, n_entries, entries_blob, disk_guid=b'\xaa'*16):
    arr_crc = zlib.crc32(entries_blob) & 0xffffffff
    def pack(crc):
        return (b'EFI PART' + bytes([0, 0, 1, 0]) + struct.pack('<II', 92, crc) + b'\0'*4 +
                struct.pack('<QQQQ', primary_lba, backup_lba, first_usable, last_usable) + disk_guid +
                struct.pack('<QIII', entry_lba, n_entries, 128, arr_crc))
    h0 = pack(0); assert len(h0) == 92
    return pack(zlib.crc32(h0) & 0xffffffff)

def protective_mbr(S, N):
    mbr = bytearray(S)
    # one 0xEE partition covering LBA 1..N-1
    mbr[446:462] = bytes([0x00, 0x00, 0x02, 0x00, 0xEE, 0xFF, 0xFF, 0xFF]) + struct.pack('<II', 1, N - 1)
    mbr[510:512] = b'\x55\xaa'
    return bytes(mbr)

def image(S, N, parts):
    n_entries = 4
    arr = b''.join(parts) + entry(ZERO_GUID, '', 0, 0, uniq=bytes(16)) * (n_entries - len(parts))
    assert len(arr) == 512
    arr_sectors = (len(arr) - 1) // S + 1
    first_usable = 2 + arr_sectors
    last_usable = N - arr_sectors - 2
    backup_entry_lba = last_usable + 1
    img = bytearray(S * N)
    img[0:S] = protective_mbr(S, N)
    img[S:S+92] = header(1, N - 1, first_usable, last_usable, 2, n_entries, arr)
    img[2*S:2*S+len(arr)] = arr
    img[backup_entry_lba*S:backup_entry_lba*S+len(arr)] = arr
    img[(N-1)*S:(N-1)*S+92] = header(N - 1, 1, first_usable, last_usable, backup_entry_lba, n_entries, arr)
    return bytes(img), first_usable, last_usable

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    seeds = {}
    # 512-byte sectors, 16 sectors = 8 KiB
    img, fu, lu = image(512, 16, [entry(BOTTLEROCKET_ROOT, 'BOTTLEROCKET-ROOT-A', 3, 6),
                                  entry(BOTTLEROCKET_DATA, 'BOTTLEROCKET-DATA', 7, 13)])
    seeds['gpt512-bottlerocket-root.img'] = img
    img, fu, lu = image(512, 16, [entry(LINUX_FS, 'BOTTLEROCKET-STUFF', fu if False else 3, 13)])
    seeds['gpt512-bottlerocket-name.img'] = img
    img, fu, lu = image(512, 16, [entry(LINUX_FS, 'data', 3, 13)])
    seeds['gpt512-linux-data.img'] = img
    img, fu, lu = image(512, 16, [entry(EFI_SYSTEM, 'EFI', 3, 5), entry(LINUX_FS, 'rootfs', 6, 13)])
    seeds['gpt512-efi-linux.img'] = img
    # 4096-byte sectors, 6 sectors = 24 KiB (exercises GPT::find_from's 4096 retry)
    img, fu, lu = image(4096, 6, [entry(BOTTLEROCKET_ROOT, 'BOTTLEROCKET-ROOT-B', 3, 3)])
    seeds['gpt4k-bottlerocket-root.img'] = img
    # a plain MBR-only 4 KiB disk (no GPT anywhere) -> ephemeral
    seeds['mbr-only-4k.img'] = protective_mbr(512, 8) + bytes(512 * 7)
    for name, data in seeds.items():
        with open(os.path.join(outdir, name), 'wb') as f:
            f.write(data)
        print(f"{name}: {len(data)} bytes")

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'seeds')
