# naos-data-key

Read and update NAOS key records in a `misc` partition. The utility manages
redundant userdata Trusted Key records and system key import/blob records.
Cryptographic authentication of system blobs is handled by
[rk-huk-keybox](../rk-huk-keybox/README.md).

## Build

Requirements: Linux C headers, a C compiler, GNU Make, and OpenSSL `libcrypto`
headers and libraries. Run these commands from this directory:

```sh
make
./build/naos-data-key --help
```

For cross-compilation, use a target compiler and a matching sysroot containing
OpenSSL:

```sh
make CC="$TARGET_CC" SYSROOT="$TARGET_SYSROOT" \
    OUTPUT=build/naos-data-key-target
```

`CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `LDLIBS`, and `OUTPUT` can also be overridden.
The target requires a compatible `libcrypto` at runtime.

## Userdata records

```text
naos-data-key status --device DEVICE
naos-data-key init --device DEVICE --blob SEALED_HEX_FILE
naos-data-key export --device DEVICE --output SEALED_HEX_FILE
naos-data-key ready --device DEVICE
```

`status` prints `empty`, `initializing`, or `ready`. `init` writes both redundant
records when their storage is empty. `ready` marks initialization complete and
repairs the redundant records. `export` writes the stored opaque hexadecimal
blob to a file.

The device must be exactly 4 MiB. These subcommands also accept
`--allow-regular-file` for a file-backed record store of that size.

## System records

```text
naos-data-key system read DEVICE {import|blob-a|blob-b} OUTPUT_RECORD
naos-data-key system write DEVICE {blob-a|blob-b} INPUT_RECORD EXPECTED_RECORD
naos-data-key system erase DEVICE import EXPECTED_RECORD
```

System operations require a resolved block-partition path. The partition must
be named `misc` and be exactly 4 MiB. Access requires the appropriate device
permissions, normally root.

Records are complete 64 KiB windows. `read` creates a new output file with
owner-only permissions. `INPUT_RECORD` and `EXPECTED_RECORD` must each be a
private, regular 64 KiB file with one hard link. Symbolic links are rejected.

Before a write or erase, the current window must match `EXPECTED_RECORD` byte
for byte. A mismatch aborts the operation. Successful updates are synchronized
and read back for verification.

`write` accepts a keybox envelope followed by zero padding to fill the window.
It validates the record structure. Use `rk-huk-keybox` to authenticate and
unseal the envelope. `erase` clears only the system import window.

## Storage layout

Offsets are relative to the start of `misc`. Each window is 64 KiB.

| Offset | Record | Operations |
| --- | --- | --- |
| `0x20000` | System key import | Read, erase |
| `0x30000` | Userdata Trusted Key A | Userdata commands |
| `0x40000` | Userdata Trusted Key B | Userdata commands |
| `0x50000` | System keybox blob A | Read, write |
| `0x60000` | System keybox blob B | Read, write |

## License

[MIT](LICENSE).
