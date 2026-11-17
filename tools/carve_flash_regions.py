import os
#!/usr/bin/env python3
"""Carve byte-exact physical and logical regions from the immutable flash dump."""
import csv
import hashlib
from pathlib import Path

ROOT = Path(os.environ.get("SITI_PRIVATE_ROOT", "."))
IMAGE = ROOT / 'siti-msd5043-full-16MiB.bin'
CARVES = ROOT / 'derived/flash-carves'
MAPS = [ROOT / 'reports/flash-coverage-map.csv', ROOT / 'reports/flash-logical-map.csv']
MANIFEST_FIELDS = ['region_id', 'filename', 'start_offset', 'end_offset_exclusive', 'length',
                   'sha256', 'structure', 'classification', 'extraction_method',
                   'source_dump_sha256', 'evidence_reference', 'publication_classification', 'region_type']


def main() -> None:
    raw = IMAGE.read_bytes()
    source_sha = hashlib.sha256(raw).hexdigest()
    CARVES.mkdir(parents=True, exist_ok=True)
    for stale in CARVES.glob('*.bin'):
        stale.unlink()

    rows = []
    physical = []
    for path in MAPS:
        with path.open(newline='', encoding='utf-8') as f:
            for source in csv.DictReader(f):
                start = int(source['start_offset'], 16)
                end = int(source['end_offset_exclusive'], 16)
                if not (0 <= start < end <= len(raw)):
                    raise ValueError(f'out-of-range slice: {source["region_id"]}')
                if source['region_type'] == 'PHYSICAL' and any(r['region_type'] == 'PHYSICAL' and
                       not (end <= int(r['start_offset'], 16) or start >= int(r['end_offset_exclusive'], 16))
                       for r in physical):
                    raise ValueError(f'physical overlap: {source["region_id"]}')
                if source['region_type'] == 'PHYSICAL':
                    physical.append(source)
                data = raw[start:end]
                out = CARVES / source['filename']
                out.write_bytes(data)
                out_hash = hashlib.sha256(out.read_bytes()).hexdigest()
                expected = source['sha256']
                if out_hash != expected or data != raw[start:end]:
                    raise ValueError(f'extraction mismatch: {source["region_id"]}')
                rows.append({
                    'region_id': source['region_id'], 'filename': source['filename'],
                    'start_offset': source['start_offset'], 'end_offset_exclusive': source['end_offset_exclusive'],
                    'length': len(data), 'sha256': out_hash, 'structure': source['structure'],
                    'classification': source['classification'],
                    'extraction_method': 'byte-exact slice of immutable master dump via carve_flash_regions.py',
                    'source_dump_sha256': source_sha,
                    'evidence_reference': source['evidence_source'],
                    'publication_classification': source['publication_classification'],
                    'region_type': source['region_type'],
                })
    with (CARVES / 'manifest.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS, lineterminator='\n')
        w.writeheader(); w.writerows(rows)
    with (ROOT / 'reports/flash-region-manifest.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS, lineterminator='\n')
        w.writeheader(); w.writerows(rows)
    print(f'carves={len(rows)} physical={len(physical)} bytes={sum(r["length"] for r in rows)}')


if __name__ == '__main__':
    main()
