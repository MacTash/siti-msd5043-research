# SITI MSD5043 firmware research

Practical research collection for the SITI HD+ CCH-8000DEI set-top box
(MStar MSD5043 / Kronus, MIPS 34Kf family).

## Firmware

The original 16 MiB SPI NOR dump is retained privately and integrity-verified. Its exact
fingerprint is withheld; no sanitized or relabelled substitute is distributed. Selected,
reviewed binary extracts are in `extracted/`.

## Acquisition

`acquisition/` contains the MStar ISP ESP32 firmware source and host-side read-only
acquisition tool. The dump was obtained through the SoC ISP slave at I2C `0x49` using
128-byte READ transactions; USB serial carried data to the host. The UART bridge project
was used separately for boot/runtime logs.

## Files

- `acquisition/` - ESP32 ISP firmware source and host acquisition tool.
- `captures/` - redacted boot and runtime UART logs.
- `extracted/` - flash maps, region manifest and selected binary extracts.
- `extracted-media/` - reconstructed viewable media (PNG, GIF, MP4, MPEG-TS) derived from the boot frame; not original firmware files.
- `tools/` - LZSS decoder, flash inventory, carving and verification scripts, database parsers.

## Usage

```sh
python3 tools/gam_decode.py --help
python3 tools/flash_inventory.py --help
```

## Known unresolved areas

Boot chain, firmware byte order, executable boundaries, the FE-only 0x808 span, GAM alpha
semantics and several high-entropy flash regions remain UNKNOWN.

See `SHA256SUMS` for distributed binary checksums.
