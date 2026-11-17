#!/usr/bin/env python3
"""Bounded extractor for the observed xpdr0001 table; fields remain unnamed."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

REGIONS = {"A": 0x800000, "B": 0x870000}
REGION_SIZE = 0x70000
MARKER = b"xpdr0001"
FOLLOWING_MARKER = b"serv0001"
HEADER_SIZE = 0x18


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def parse_region(image: bytes, *, label: str, base: int,
                 region_size: int = REGION_SIZE) -> dict[str, Any]:
    end = base + region_size
    if base < 0 or end > len(image):
        raise ValueError(f"{label}: region outside input image")
    marker_abs = base + 4
    if image[marker_abs:marker_abs + len(MARKER)] != MARKER:
        raise ValueError(f"{label}: expected xpdr0001 at 0x{marker_abs:X}")
    stride, count = struct.unpack_from("<II", image, base + 0x10)
    if stride == 0 or count == 0:
        raise ValueError(f"{label}: invalid zero stride or count")
    data_abs = base + HEADER_SIZE
    table_end = data_abs + stride * count
    if table_end > end:
        raise ValueError(f"{label}: table exceeds region end")
    following = image.find(FOLLOWING_MARKER, data_abs, end)
    if following >= 0 and following < table_end:
        raise ValueError(
            f"{label}: serv0001 at 0x{following:X} overlaps declared entries"
        )

    entries = []
    for index in range(count):
        start = data_abs + index * stride
        raw = image[start:start + stride]
        if len(raw) != stride:
            raise ValueError(f"{label}: truncated entry {index}")
        entry = {
            "region": label,
            "index": index,
            "image_offset": start,
            "relative_offset": start - base,
            "length": stride,
            "sha256": sha256(raw),
            "u16_le_candidates": [
                int.from_bytes(raw[o:o + 2], "little")
                for o in range(0, stride - 1, 2)
            ],
            "u32_le_candidates": [
                int.from_bytes(raw[o:o + 4], "little")
                for o in range(0, stride - 3, 4)
            ],
            "raw_hex": raw.hex(),
        }
        entries.append(entry)

    return {
        "region": label,
        "base": base,
        "region_size": region_size,
        "prefix_hex": image[base:base + 4].hex(),
        "marker_offset": marker_abs,
        "header_hex": image[base:base + HEADER_SIZE].hex(),
        "stride_candidate": stride,
        "count_candidate": count,
        "data_offset": data_abs,
        "table_end": table_end,
        "following_marker_offset": following if following >= 0 else None,
        "following_marker_gap": following - table_end if following >= 0 else None,
        "entries": entries,
    }


def parse_image(image: bytes) -> dict[str, Any]:
    regions = {
        label: parse_region(image, label=label, base=base)
        for label, base in REGIONS.items()
    }
    a, b = regions["A"]["entries"], regions["B"]["entries"]
    if (regions["A"]["stride_candidate"], regions["A"]["count_candidate"]) != (regions["B"]["stride_candidate"], regions["B"]["count_candidate"]):
        raise ValueError("A/B entry geometries differ")
    if len(a) != len(b):
        raise ValueError("A/B entry counts differ")
    changed = [i for i, (x, y) in enumerate(zip(a, b))
               if x["sha256"] != y["sha256"]]
    return {
        "input_size": len(image),
        "input_sha256": sha256(image),
        "regions": regions,
        "comparison": {
            "entry_count": len(a),
            "identical_entries": len(a) - len(changed),
            "changed_entry_indices": changed,
        },
    }


def write_outputs(result: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    summary = {k: v for k, v in result.items() if k != "regions"}
    summary["regions"] = {
        name: {k: v for k, v in region.items() if k != "entries"}
        for name, region in result["regions"].items()
    }
    (out / "xpdr-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    entries = [e for region in result["regions"].values()
               for e in region["entries"]]
    with (out / "xpdr-entries.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "region", "index", "image_offset", "relative_offset",
            "length", "sha256", "u16_le_candidates",
            "u32_le_candidates", "raw_hex",
        ])
        writer.writeheader()
        for entry in entries:
            row = dict(entry)
            row["u16_le_candidates"] = json.dumps(row["u16_le_candidates"])
            row["u32_le_candidates"] = json.dumps(row["u32_le_candidates"])
            writer.writerow(row)
    (out / "xpdr-entries.json").write_text(json.dumps(entries, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = parse_image(args.image.read_bytes())
    write_outputs(result, args.out)
    print(json.dumps({
        "input_sha256": result["input_sha256"],
        "entry_count": result["comparison"]["entry_count"],
        "identical_entries": result["comparison"]["identical_entries"],
        "changed_entry_indices": result["comparison"]["changed_entry_indices"],
        "output": str(args.out),
    }, indent=2))


if __name__ == "__main__":
    main()
