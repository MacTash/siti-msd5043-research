import os
#!/usr/bin/env python3
"""Validate physical coverage and prove byte-identical reconstruction from carves."""
import csv
import hashlib
import tempfile
from pathlib import Path

ROOT = Path(os.environ.get("SITI_PRIVATE_ROOT", "."))
IMAGE = ROOT / 'siti-msd5043-full-16MiB.bin'
MAP = ROOT / 'reports/flash-coverage-map.csv'
CARVES = ROOT / 'derived/flash-carves'
OUT = ROOT / 'reports/flash-coverage-verification.md'


def main() -> None:
    raw = IMAGE.read_bytes()
    source_sha = hashlib.sha256(raw).hexdigest()
    with MAP.open(newline='', encoding='utf-8') as f:
        rows = sorted(csv.DictReader(f), key=lambda r: int(r['start_offset'], 16))
    errors = []
    cursor = 0
    for r in rows:
        start = int(r['start_offset'], 16)
        end = int(r['end_offset_exclusive'], 16)
        if start != cursor:
            errors.append(f'gap/overlap at 0x{start:X} (expected 0x{cursor:X})')
        if end <= start:
            errors.append(f'bad interval {r["region_id"]}')
        cursor = end
    if rows[0]['start_offset'] != '0x00000000':
        errors.append('first interval does not start at zero')
    if cursor != len(raw):
        errors.append(f'coverage ends at 0x{cursor:X}, expected 0x{len(raw):X}')

    with tempfile.TemporaryDirectory() as tmp:
        rebuilt = Path(tmp) / 'reconstructed.bin'
        h = hashlib.sha256()
        with rebuilt.open('wb') as out:
            for r in rows:
                carve = CARVES / r['filename']
                if not carve.exists():
                    errors.append(f'missing carve {carve.name}')
                    continue
                data = carve.read_bytes()
                if len(data) != int(r['length']):
                    errors.append(f'length mismatch {carve.name}')
                if hashlib.sha256(data).hexdigest() != r['sha256']:
                    errors.append(f'hash mismatch {carve.name}')
                out.write(data)
                h.update(data)
        rebuilt_sha = h.hexdigest()
    identical = rebuilt_sha == source_sha and not errors

    OUT.write_text(
        '# Physical flash coverage verification\n\n'
        f'- Original SHA256: `{source_sha}`\n'
        f'- Reconstructed SHA256: `{rebuilt_sha}`\n'
        f'- Byte-identical: `{identical}`\n'
        f'- Intervals: {len(rows)}\n'
        f'- Total covered bytes: {cursor}\n'
        f'- Errors: {errors or "NONE"}\n\n'
        'The reconstruction concatenates only the physical, non-overlapping carves in offset order.\n',
        encoding='utf-8')
    print(f'identical={identical} intervals={len(rows)} errors={errors}')


if __name__ == '__main__':
    main()
