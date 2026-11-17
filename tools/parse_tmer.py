#!/usr/bin/env python3
"""Bounded parser for observed tmer0001 copies; slot fields remain unknown."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

REGION_A = 0x800000
REGION_B = 0x870000
REGION_SIZE = 0x70000
TABLES = {
    "primary_A": (REGION_A, 0x60CA4),
    "primary_B": (REGION_B, 0x60CA4),
    "secondary_B": (REGION_B, 0x64994),
}
MARKER = b"tmer0001"
HEADER_SIZE = 0x18


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def parse_table(image: bytes, *, label: str, absolute_offset: int,
                region_end: int) -> dict[str, Any]:
    if absolute_offset < 0 or region_end > len(image) or absolute_offset >= region_end:
        raise ValueError(f"{label}: table outside image region")
    if image[absolute_offset:absolute_offset + 8] != MARKER:
        raise ValueError(f"{label}: tmer0001 marker absent at 0x{absolute_offset:X}")
    if absolute_offset + HEADER_SIZE > region_end:
        raise ValueError(f"{label}: header outside region")
    version, stride, count, sentinel = struct.unpack_from(
        "<IIII", image, absolute_offset + 8
    )
    if version == 0 or stride == 0 or count == 0:
        raise ValueError(f"{label}: invalid zero header field")
    data_start = absolute_offset + HEADER_SIZE
    table_end = data_start + stride * count
    if table_end > region_end:
        raise ValueError(f"{label}: table exceeds region end")
    records = []
    for index in range(count):
        start = data_start + index * stride
        raw = image[start:start + stride]
        if len(raw) != stride:
            raise ValueError(f"{label}: truncated slot {index}")
        records.append({
            "table": label,
            "index": index,
            "image_offset": start,
            "relative_to_region": start - (region_end - REGION_SIZE),
            "length": stride,
            "sha256": sha256(raw),
            "raw_hex": raw.hex(),
        })
    return {
        "table": label,
        "marker_offset": absolute_offset,
        "header_raw_hex": image[absolute_offset:absolute_offset + HEADER_SIZE].hex(),
        "version_candidate": version,
        "stride_candidate": stride,
        "count_candidate": count,
        "sentinel_candidate": sentinel,
        "data_start": data_start,
        "table_end": table_end,
        "table_sha256": sha256(image[data_start:table_end]),
        "records": records,
    }


def parse_image(image: bytes) -> dict[str, Any]:
    tables = {}
    for name, (base, relative) in TABLES.items():
        tables[name] = parse_table(
            image,
            label=name,
            absolute_offset=base + relative,
            region_end=base + REGION_SIZE,
        )
    geometry = {
        (t["stride_candidate"], t["count_candidate"])
        for t in tables.values()
    }
    if len(geometry) != 1:
        raise ValueError("timer table copy geometries differ")
    comparisons = {}
    pairs = [("primary_A", "primary_B"),
             ("primary_A", "secondary_B"),
             ("primary_B", "secondary_B")]
    for left, right in pairs:
        a, b = tables[left]["records"], tables[right]["records"]
        changed = []
        if len(a) != len(b):
            raise ValueError(f"{left}/{right} record counts differ")
        for index, (ra, rb) in enumerate(zip(a, b)):
            xa, xb = bytes.fromhex(ra["raw_hex"]), bytes.fromhex(rb["raw_hex"])
            offsets = [i for i, (x, y) in enumerate(zip(xa, xb)) if x != y]
            if offsets:
                changed.append({"index": index, "different_offsets": offsets})
        comparisons[f"{left}_vs_{right}"] = {
            "changed_slots": changed,
            "different_byte_count": sum(len(x["different_offsets"]) for x in changed),
        }
    return {
        "input_size": len(image),
        "input_sha256": sha256(image),
        "tables": tables,
        "comparisons": comparisons,
    }


def write_outputs(result: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    summary = {k: v for k, v in result.items() if k != "tables"}
    summary["tables"] = {
        name: {k: v for k, v in table.items() if k != "records"}
        for name, table in result["tables"].items()
    }
    (out / "tmer-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    records = [r for table in result["tables"].values()
               for r in table["records"]]
    with (out / "tmer-slots.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "table", "index", "image_offset", "relative_to_region",
            "length", "sha256", "raw_hex",
        ])
        writer.writeheader()
        writer.writerows(records)
    (out / "tmer-slots.json").write_text(json.dumps(records, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = parse_image(args.image.read_bytes())
    write_outputs(result, args.out)
    print(json.dumps({
        "input_sha256": result["input_sha256"],
        "table_hashes": {k: v["table_sha256"] for k, v in result["tables"].items()},
        "comparisons": result["comparisons"],
        "output": str(args.out),
    }, indent=2))


if __name__ == "__main__":
    main()
