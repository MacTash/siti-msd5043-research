#!/usr/bin/env python3
"""Extract bounded raw resource ranges to a private analysis directory."""
import argparse, csv, hashlib
from pathlib import Path
from parse_resource_catalog import parse_catalog, RESOURCE_BASE


def extract(data: bytes, outdir: Path, start=0x650018, count=281, base=RESOURCE_BASE):
    rows = parse_catalog(data, start=start, count=count, base=base)
    outdir.mkdir(parents=True, exist_ok=True)
    results = []
    for row in rows:
        name = row["filename_candidate"]
        if not row["filename_candidate_valid_printable"] or not row["candidate_range_in_image"]:
            continue
        # Names are fixed-width ASCII from the firmware; reduce to a safe basename.
        safe = "".join(c if c.isalnum() or c in "._- " else "_" for c in name).strip(" .")
        if not safe:
            continue
        offset = row["payload_offset_absolute_candidate"]
        size = row["field_04_u32le_candidate"]
        blob = data[offset:offset + size]
        if len(blob) != size:
            raise ValueError(f"short range at catalog index {row['index']}")
        target = outdir / f"{row['index']:03d}_{safe}.raw"
        target.write_bytes(blob)
        results.append({"index": row["index"], "name_candidate": name,
                        "offset_relative": f"0x{row['payload_offset_relative_candidate']:X}",
                        "offset_absolute": f"0x{offset:X}",
                        "stored_size_candidate": size,
                        "output_size_candidate": row["field_08_u32le_candidate"],
                        "sha256": hashlib.sha256(blob).hexdigest(), "path": target.name})
    with (outdir / "manifest.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0]) if results else [])
        if results:
            w.writeheader(); w.writerows(results)
    (outdir / "README.txt").write_text(
        "Private raw ranges copied from the firmware image using directory candidate fields.\n"
        "Field +0x00 is a relative offset; the resource base is 0x650000.\n"
        "These blobs are not claimed to be decoded assets; field meanings and formats remain under investigation.\n"
        "Original firmware was read only.\n")
    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("image", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--base", type=lambda x: int(x, 0), default=RESOURCE_BASE)
    a = p.parse_args()
    rows = extract(a.image.read_bytes(), a.output, base=a.base)
    print(f"extracted {len(rows)} bounded named ranges to {a.output}")


if __name__ == "__main__":
    main()
