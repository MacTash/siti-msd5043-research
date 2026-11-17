import argparse
import json
import struct
from pathlib import Path

WINDOW_SIZE = 4096
SOURCE_BIAS = 18
MAGIC = 0x444F0006
VERSION = 133


def decode(data: bytes) -> bytes:
    window = bytearray(WINDOW_SIZE)
    out = bytearray()
    ip = 0
    pos = 0
    while ip < len(data):
        flags = data[ip]
        ip += 1
        for bit in range(8):
            if flags & (1 << bit):
                if ip >= len(data):
                    return bytes(out)
                value = data[ip]
                ip += 1
            else:
                if ip + 1 >= len(data):
                    return bytes(out)
                a, b = data[ip], data[ip + 1]
                ip += 2
                source = ((b & 0xF0) << 4 | a) + SOURCE_BIAS
                for _ in range((b & 0x0F) + 3):
                    value = window[source & (WINDOW_SIZE - 1)]
                    out.append(value)
                    window[pos & (WINDOW_SIZE - 1)] = value
                    pos += 1
                    source += 1
                continue
            out.append(value)
            window[pos & (WINDOW_SIZE - 1)] = value
            pos += 1
    return bytes(out)


def header(data: bytes) -> dict:
    if len(data) < 24:
        return {}
    magic, version, height, width, pixel_count, pixel_format = struct.unpack("<6I", data[:24])
    return {
        "magic": magic,
        "magic_hex": f"0x{magic:08X}",
        "version": version,
        "height": height,
        "width": width,
        "pixel_count": pixel_count,
        "pixel_format": pixel_format,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode a SITI/MSD5043 resource LZSS stream.")
    parser.add_argument("input")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    raw = Path(args.input).read_bytes()
    out = decode(raw)
    info = header(out)
    info["stored_bytes"] = len(raw)
    info["decoded_bytes"] = len(out)
    info["header_valid"] = info.get("magic") == MAGIC and info.get("version") == VERSION
    info["pixel_bytes"] = max(0, len(out) - 24)
    if args.output:
        Path(args.output).write_bytes(out)
    print(json.dumps(info, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
