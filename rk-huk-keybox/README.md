# rk-huk-keybox

Seal and unseal an existing 32-byte system key using Rockchip OP-TEE. A client
application handles files; a trusted application derives a wrapping key with
`rk_derive_ta_unique_key` and protects the supplied key with AES-256-GCM.

Each blob is tied to the device and TA identity that created it. The blob can
be stored by the caller, including through
[naos-data-key](../naos-data-key/README.md).

## Build

Requirements:

- Python 3 with `pycryptodomex` and `pyelftools`.
- GNU Make and a host GCC compiler.
- An ARM64 GCC toolchain and matching target sysroot with `libteec` headers and libraries.
- A Rockchip `rk_tee_user` SDK checkout with `v2/export-ta_arm64` and
  `v2/ta/rk_public_api/rk_derive_key_api.{c,h}`.

The SDK dependency is
[rk_tee_user](https://github.com/mixtile-rockchip/mixtile-sdk-android-rk-platform-system-rk_tee_user)
at revision `957bd3aa88589a2c78bc12867ef082675f464e19`.

From this directory, build with:

```sh
python3 build.py \
    --sdk-source "$RK_TEE_SOURCE" \
    --cc "$TARGET_CC" \
    --sysroot "$TARGET_SYSROOT"
```

Set the variables to the SDK checkout, target GCC executable, and target
sysroot. The compiler executable name must end in `gcc`.

The default output directory is `build/`. Deployment files are:

| File | Description |
| --- | --- |
| `keybox_app` | ARM64 client executable |
| `<uuid>.ta` | Signed trusted application |
| `ta.uuid` | TA UUID for installation |

Use `--output` to select an output directory and `--python-deps` to add a
Python module search directory. Run `python3 build.py --help` for all options.

TA signing uses the SDK devkit default. To select a signing key, add
`--ta-sign-key "$TA_SIGNING_PEM"`. The device's OP-TEE firmware must trust the
corresponding TA signing key and support the Rockchip key derivation API.

## Install

The target needs a compatible `libteec`, a running `tee-supplicant`, and OP-TEE
devices such as `/dev/tee0` and `/dev/teepriv0`. Install the TA into the
supplicant's configured loading directory, commonly `/lib/optee_armtz`:

```sh
sudo install -m 0755 build/keybox_app /usr/bin/keybox_app
keybox_uuid=$(cat build/ta.uuid)
sudo install -d /lib/optee_armtz
sudo install -m 0644 "build/$keybox_uuid.ta" /lib/optee_armtz/
```

## Seal and unseal

`system.key` must contain exactly 64 lowercase hexadecimal characters with no
newline, representing the existing 32-byte key.

```sh
umask 077
keybox_app seal system.key system.blob
keybox_app unseal system.blob restored.key
cmp system.key restored.key
```

`system.blob` is a 100-byte binary envelope. `restored.key` contains the same
64 hexadecimal characters as the original input.

Input files must be private regular files with one hard link; symbolic links
are rejected. Output paths must not already exist. Outputs are created with
owner-only permissions. Authentication failure returns a nonzero exit status;
plaintext output is written after successful authentication.

## TA identity

The default UUID is `6bada6f2-74f7-49cc-8d0f-4195a3c62fb0`. Keep this identity
when updating devices with existing blobs. `--uuid` selects another identity;
blobs created with the previous identity cannot be unsealed by the new one.

## Licenses

- Client: [GPL-2.0-only](LICENSES/GPL-2.0-only.txt).
- TA and build support files: [BSD-2-Clause](LICENSES/BSD-2-Clause.txt).

See [LICENSE](LICENSE) for the file-level license declarations.
