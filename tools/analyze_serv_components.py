#!/usr/bin/env python3
"""Summarize candidate component records in serv0001 without assigning semantics."""
import argparse, csv, json, struct
from collections import Counter
from pathlib import Path


def analyze(data: bytes, start: int = 0x801930, count: int = 1300, stride: int = 300):
    if start < 0 or count < 0 or stride < 0 or start + count * stride > len(data):
        raise ValueError("record array exceeds input")
    kind_counts, language_counts = Counter(), Counter()
    rows = []
    candidate_count = 0
    typed_pid_count = 0
    exact_empty_count = 0
    for index in range(count):
        record = data[start + index * stride:start + (index + 1) * stride]
        name_raw = record[:32].split(b"\0", 1)[0]
        name = name_raw.decode("ascii", "replace")
        for block_index in range(16):
            raw = record[0x40 + block_index * 12:0x4c + block_index * 12]
            kind, pid = struct.unpack_from("<HH", raw)
            lang = raw[4:8]
            reserved = raw[8:12]
            # Exact observed shape of the common empty slot is retained separately.
            if raw == bytes.fromhex("0000ff1f0000000000000000"):
                exact_empty_count += 1
            kind_counts[kind] += 1
            lang_valid = (len(lang) == 4 and all(97 <= x <= 122 for x in lang[:3])
                          and lang[3] == 0)
            accepted_lang = (all(97 <= x <= 122 for x in lang[:3]) and lang[3] in (0, 32, 255))
            if accepted_lang:
                language_counts[(kind, lang[:3].decode("ascii"))] += 1
            type_pid_candidate = kind in (1, 4, 0x81, 6) and pid <= 0x1fff
            candidate = type_pid_candidate and accepted_lang and reserved == bytes(4)
            typed_pid_count += int(type_pid_candidate)
            candidate_count += int(candidate)
            if raw == bytes.fromhex("0000ff1f0000000000000000"):
                continue
            rows.append({
                "record_index": index, "name_candidate": name,
                "block_index": block_index, "block_offset": f"+0x{0x40 + block_index*12:02X}",
                "raw_hex": raw.hex(), "u16_le_0_candidate": kind,
                "u16_le_2_candidate": pid, "u16_le_2_within_13_bits": pid <= 0x1fff,
                "language_candidate": lang[:3].decode("ascii", "replace") if accepted_lang else "",
                "type_and_pid_candidate": type_pid_candidate,
                "component_shape_candidate": candidate,
                "trailing_u32_le_candidate": struct.unpack_from("<I", raw, 8)[0],
            })
    summary = {
        "record_count": count,
        "empty_slot_pattern_hex": "0000ff1f0000000000000000",
        "exact_common_empty_slot_count": exact_empty_count,
        "slots_differing_from_common_empty_pattern": len(rows),
        "type_and_pid_candidate_count": typed_pid_count,
        "language_and_zero_tail_shape_count": candidate_count,
        "candidate_u16_le_0_counts": {f"0x{k:04x}": v for k, v in sorted(kind_counts.items())},
        "three_letter_lowercase_language_candidate_by_value": {
            f"0x{k:04x}": dict(sorted({lang: n for (kind, lang), n in language_counts.items() if kind == k}.items()))
            for k in sorted({kind for kind, _ in language_counts})
        },
        "interpretation": "Candidate component entries only; offsets and raw bytes are preserved; field semantics unconfirmed.",
    }
    return summary, rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("image", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    data = args.image.read_bytes()
    summary, rows = analyze(data)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (args.output / "candidate-blocks.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else [])
        if rows: w.writeheader(); w.writerows(rows)
    print(json.dumps(summary, indent=2))

if __name__ == "__main__": main()
