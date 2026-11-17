#!/usr/bin/env python3
"""Parse the candidate 48-byte resource directory while preserving raw slots."""
import argparse, csv, json, struct
from pathlib import Path

START = 0x650018
COUNT = 281
STRIDE = 0x30
RESOURCE_BASE = 0x650000


def parse_catalog(data: bytes, start: int = START, count: int = COUNT,
                  stride: int = STRIDE, base: int = RESOURCE_BASE):
    if start < 0 or count < 0 or stride < 48 or start + count * stride > len(data):
        raise ValueError("catalog slots exceed input or stride is too short")
    if base < 0:
        raise ValueError("base must be non-negative")
    entries = []
    for index in range(count):
        pos = start + index * stride
        raw = data[pos:pos + 48]
        fields = struct.unpack_from("<IIII", raw, 0)
        name_raw = raw[16:48]
        name_bytes = name_raw.split(b"\0", 1)[0]
        valid_name = bool(name_bytes) and all(32 <= x <= 126 for x in name_bytes)
        offset, stored_size, output_size, flags = fields
        absolute = base + offset
        in_bounds = absolute <= len(data) and stored_size <= len(data) - absolute
        entries.append({
            "index": index, "catalog_offset": pos, "raw_hex": raw.hex(),
            "field_00_u32le_candidate": offset,
            "field_04_u32le_candidate": stored_size,
            "field_08_u32le_candidate": output_size,
            "field_0c_u32le_candidate": flags,
            "filename_candidate": name_bytes.decode("ascii", "replace") if valid_name else "",
            "filename_candidate_valid_printable": valid_name,
            "payload_offset_relative_candidate": offset,
            "payload_offset_absolute_candidate": absolute,
            "candidate_range_in_image": in_bounds,
        })
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=START)
    ap.add_argument("--count", type=int, default=COUNT)
    ap.add_argument("--base", type=lambda x: int(x, 0), default=RESOURCE_BASE)
    args = ap.parse_args()
    data = args.image.read_bytes()
    entries = parse_catalog(data, args.start, args.count, base=args.base)
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "catalog.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(entries[0]))
        w.writeheader(); w.writerows(entries)
    (args.output / "catalog.json").write_text(json.dumps(entries, indent=2) + "\n")
    named = [e for e in entries if e["filename_candidate_valid_printable"]]
    summary = {"start": hex(args.start), "base": hex(args.base), "slot_count": args.count,
               "stride": hex(STRIDE), "named_slots": len(named),
               "unlabelled_slots": args.count - len(named),
               "in_bounds_ranges": sum(e["candidate_range_in_image"] for e in entries),
               "note": "Field semantics and malformed slot interpretation remain unresolved; "
                       "field +0x00 is treated as relative to the resource base."}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
