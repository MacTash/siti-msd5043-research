#!/usr/bin/env python3
"""Bounded extractor for the observed SITI serv0001 table.

Field semantics are deliberately not assigned. Raw record bytes are preserved.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

DEFAULT_REGIONS = {
    "A": {"base": 0x800000, "marker_offset": 0x191C},
    "B": {"base": 0x870000, "marker_offset": 0x191C},
}
REGION_SIZE = 0x70000
MARKER = b"serv0001"
NEXT_MARKER = b"tmer0001"
HEADER_SIZE = 0x14
NAME_CANDIDATE_SIZE = 0x20


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def printable_candidate(raw: bytes) -> str:
    raw = raw.split(b"\0", 1)[0]
    return "".join(chr(b) if 0x20 <= b < 0x7f else "\uFFFD" for b in raw)


def parse_region(
    image: bytes,
    *,
    label: str,
    base: int,
    marker_offset: int,
    region_size: int = REGION_SIZE,
) -> dict[str, Any]:
    marker_abs = base + marker_offset
    region_end = base + region_size
    if base < 0 or region_end > len(image):
        raise ValueError(f"{label}: region outside input image")
    if marker_abs + HEADER_SIZE > region_end:
        raise ValueError(f"{label}: header outside region")
    if image[marker_abs:marker_abs + len(MARKER)] != MARKER:
        raise ValueError(f"{label}: expected serv0001 at 0x{marker_abs:X}")

    version, stride, count = struct.unpack_from("<III", image, marker_abs + 8)
    if version == 0 or stride == 0 or count == 0:
        raise ValueError(f"{label}: invalid zero header field")
    data_abs = marker_abs + HEADER_SIZE
    table_end = data_abs + stride * count
    if table_end > region_end:
        raise ValueError(
            f"{label}: table end 0x{table_end:X} exceeds region end 0x{region_end:X}"
        )

    next_marker_abs = image.find(NEXT_MARKER, data_abs, region_end)
    if next_marker_abs >= 0 and next_marker_abs < table_end:
        raise ValueError(
            f"{label}: tmer0001 at 0x{next_marker_abs:X} overlaps declared records"
        )

    records = []
    for index in range(count):
        start = data_abs + index * stride
        raw = image[start:start + stride]
        if len(raw) != stride:
            raise ValueError(f"{label}: truncated record {index}")
        pid_blocks = []
        for block_offset in range(0x40, 0x100, 12):
            block = raw[block_offset:block_offset + 12]
            if len(block) != 12:
                raise ValueError(f"{label}: record {index} too short for candidate sub-blocks")
            pid_blocks.append({
                "record_offset": block_offset,
                "raw_hex": block.hex(),
                "u16_le_candidates": [
                    int.from_bytes(block[o:o + 2], "little")
                    for o in range(0, 12, 2)
                ],
            })
        records.append({
            "region": label,
            "index": index,
            "relative_offset": start - base,
            "image_offset": start,
            "record_length": stride,
            "sha256": sha256(raw),
            "name_candidate": printable_candidate(raw[:NAME_CANDIDATE_SIZE]),
            "provider_candidate": printable_candidate(raw[0x20:0x2C]),
            "field_0x2c_u32_le_candidate": int.from_bytes(raw[0x2C:0x30], "little"),
            "field_0x2c_u16_le_candidate": int.from_bytes(raw[0x2C:0x2E], "little"),
            "field_0x2e_u16_le_candidate": int.from_bytes(raw[0x2E:0x30], "little"),
            "field_0x30_u16_le_candidate": int.from_bytes(raw[0x30:0x32], "little"),
            "field_0x32_u16_le_candidate": int.from_bytes(raw[0x32:0x34], "little"),
            "field_0x34_u16_le_candidate": int.from_bytes(raw[0x34:0x36], "little"),
            "field_0x36_u16_le_candidate": int.from_bytes(raw[0x36:0x38], "little"),
            "field_0x2c_to_0x37_raw_hex": raw[0x2C:0x38].hex(),
            "language_candidate_0x38": printable_candidate(raw[0x38:0x3B]),
            "pid_like_blocks": pid_blocks,
            "raw_hex": raw.hex(),
        })

    header_raw = image[marker_abs:marker_abs + HEADER_SIZE]
    return {
        "region": label,
        "base": base,
        "region_size": region_size,
        "marker_offset": marker_abs,
        "marker_hex": MARKER.hex(),
        "header_size": HEADER_SIZE,
        "header_raw_hex": header_raw.hex(),
        "version_candidate": version,
        "record_stride_candidate": stride,
        "record_count_candidate": count,
        "data_offset": data_abs,
        "table_end": table_end,
        "bytes_before_region_end": region_end - table_end,
        "next_marker_offset": next_marker_abs if next_marker_abs >= 0 else None,
        "next_marker_gap": next_marker_abs - table_end if next_marker_abs >= 0 else None,
        "records": records,
    }


def parse_image(image: bytes) -> dict[str, Any]:
    parsed = {
        name: parse_region(
            image,
            label=name,
            base=spec["base"],
            marker_offset=spec["marker_offset"],
        )
        for name, spec in DEFAULT_REGIONS.items()
    }
    a_records = parsed["A"]["records"]
    b_records = parsed["B"]["records"]
    if (parsed["A"]["record_stride_candidate"], parsed["A"]["record_count_candidate"]) != (parsed["B"]["record_stride_candidate"], parsed["B"]["record_count_candidate"]):
        raise ValueError("A/B record geometries differ")
    if len(a_records) != len(b_records):
        raise ValueError("A/B record counts differ")
    changed = [
        i for i, (a, b) in enumerate(zip(a_records, b_records))
        if a["sha256"] != b["sha256"]
    ]
    return {
        "input_size": len(image),
        "input_sha256": sha256(image),
        "regions": parsed,
        "comparison": {
            "record_count": len(a_records),
            "identical_records": len(a_records) - len(changed),
            "changed_record_indices": changed,
        },
    }


def write_outputs(result: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    summary = {k: v for k, v in result.items() if k != "regions"}
    summary["regions"] = {
        name: {k: v for k, v in region.items() if k != "records"}
        for name, region in result["regions"].items()
    }
    (out / "serv-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    rows = [
        record
        for region in result["regions"].values()
        for record in region["records"]
    ]
    with (out / "serv-records.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "region", "index", "relative_offset", "image_offset",
            "record_length", "sha256", "name_candidate", "provider_candidate",
            "field_0x2c_u32_le_candidate", "field_0x2c_u16_le_candidate",
            "field_0x2e_u16_le_candidate", "field_0x30_u16_le_candidate",
            "field_0x32_u16_le_candidate", "field_0x34_u16_le_candidate",
            "field_0x36_u16_le_candidate", "field_0x2c_to_0x37_raw_hex",
            "language_candidate_0x38",
            "pid_like_blocks", "raw_hex",
        ])
        writer.writeheader()
        for record in rows:
            row = dict(record)
            row["pid_like_blocks"] = json.dumps(row["pid_like_blocks"])
            writer.writerow(row)
    (out / "serv-records.json").write_text(json.dumps(rows, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = parse_image(args.image.read_bytes())
    write_outputs(result, args.out)
    print(json.dumps({
        "input_size": result["input_size"],
        "input_sha256": result["input_sha256"],
        "record_count": result["comparison"]["record_count"],
        "identical_records": result["comparison"]["identical_records"],
        "changed_record_indices": result["comparison"]["changed_record_indices"],
        "output": str(args.out),
    }, indent=2))


if __name__ == "__main__":
    main()
