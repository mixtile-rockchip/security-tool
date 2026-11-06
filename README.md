# NAOS Security Tools

Utilities for managing encrypted-storage key records in NAOS and sealing system
keys with Rockchip OP-TEE.

| Component | Purpose |
| --- | --- |
| [naos-data-key](naos-data-key/README.md) | Read and update userdata and system key records in the NAOS `misc` partition. |
| [rk-huk-keybox](rk-huk-keybox/README.md) | Seal and unseal an existing system key using a wrapping key derived inside a Rockchip trusted application. |

The keybox produces an authenticated blob tied to the device and TA identity.
The record utility stores and retrieves blobs using the NAOS `misc` layout.

## Licenses

`naos-data-key` is licensed under MIT. The `rk-huk-keybox` client is licensed
under GPL-2.0-only; its TA and build support files use BSD-2-Clause. See the
license files in each component directory.
