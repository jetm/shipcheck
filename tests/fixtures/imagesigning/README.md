# Image Signing Test Fixtures

## FIT Image Stubs

Binary stubs with FDT magic number (`0xd00dfeed`) at offset 0.

- `signed.itb` - FDT header + "signature" string in the binary (simulates a signed FIT image)
- `unsigned.itb` - FDT header without "signature" string (simulates an unsigned FIT image)

Generated with minimal 256-byte FDT structure. The implementation detects
signatures by checking for the FDT magic number and the presence of
"signature" as a string in the binary content.

## dm-verity Files

- `rootfs.hashtree` - Minimal verity hash tree (8 SHA-256 hashes, 256 bytes)

## Yocto Config Files

- `local-verity.conf` - `conf/local.conf` with `DM_VERITY_IMAGE` in `IMAGE_CLASSES`
- `local-no-signing.conf` - `conf/local.conf` without any signing or verity config
