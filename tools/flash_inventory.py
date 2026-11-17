import os
#!/usr/bin/env python3
"""P0 full-image read-only inventory of the immutable flash dump."""
import collections
import hashlib
import json
import math
import re
from pathlib import Path

ROOT = Path(os.environ.get("SITI_PRIVATE_ROOT", "."))
IMAGE = ROOT / 'siti-msd5043-full-16MiB.bin'
OUT = ROOT / 'derived/flash-analysis/flash-inventory.json'
PREVIEW = ROOT / 'derived/flash-analysis/flash-previews.txt'
WINDOW = 0x10000

SIGNATURES = {
    'PNG': b'\x89PNG\r\n\x1a\n', 'GIF89a': b'GIF89a', 'GIF87a': b'GIF87a',
    'BMP': b'BM', 'MPEG_SEQUENCE': b'\x00\x00\x01\xb3',
    'MPEG_SEQUENCE_END': b'\x00\x00\x01\xb7', 'LZMA_ALONE_D0': b'\xd0\x00\x00',
    'JBOOT': b'JBOOT', 'ESP_MAGIC': b'\xe9', 'ELF': b'\x7fELF',
}
MARKERS = [b'serv0001', b'xpdr0001', b'tmer0001', b'Loader Info', b'Update Info',
           b'System Info', b'SITI CINEMA BOOTUP HD.mpg', b'MSTAR', b'SERDB']


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = collections.Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def runs(data: bytes, value: int) -> list:
    out = []
    start = None
    for i, b in enumerate(data):
        if b == value and start is None:
            start = i
        elif b != value and start is not None:
            if i - start >= 256:
                out.append([f'0x{start:06X}', f'0x{i:06X}', i - start])
            start = None
    if start is not None and len(data) - start >= 256:
        out.append([f'0x{start:06X}', f'0x{len(data):06X}', len(data) - start])
    return out


def find_all(data: bytes, needle: bytes) -> list:
    hits, pos = [], 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            break
        hits.append(f'0x{pos:06X}')
        pos += 1
    return hits


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    raw = IMAGE.read_bytes()
    assert len(raw) == 0x1000000
    digest = sha256(raw)

    windows = []
    for start in range(0, len(raw), WINDOW):
        chunk = raw[start:start + WINDOW]
        cls = collections.Counter(chunk)
        windows.append({
            'start': f'0x{start:06X}', 'end': f'0x{start + len(chunk):06X}',
            'entropy': round(entropy(chunk), 4),
            'zero': cls[0], 'ff': cls[0xFF], 'populated': len(chunk) - cls[0] - cls[0xFF],
            'class': ('ERASED_OR_ZERO' if cls[0] + cls[0xFF] > 65000
                      else ('HIGH_ENTROPY' if entropy(chunk) > 7.0 else 'MIXED')),
        })

    strings = []
    for m in re.finditer(rb'[ -~]{8,}', raw):
        strings.append({'offset': f'0x{m.start():06X}', 'text': m.group().decode('ascii', 'replace')})

    signatures = {}
    for name, sig in SIGNATURES.items():
        signatures[name] = find_all(raw, sig)[:200]
    markers = {m.decode('ascii', 'replace'): find_all(raw, m)[:200] for m in MARKERS}

    previews = []
    for off in (0x000000, 0x010000, 0x630000, 0x650000, 0x650018, 0x6534C8,
                0x7ACBF4, 0x7E0000, 0x800000, 0x80191C, 0x860CA4, 0x870000,
                0x87191C, 0x8D0CA4, 0x8D4994, 0x928EB5, 0x960000, 0x9607F8,
                0x970000, 0x97FB45, 0x980000, 0xFE0000, 0xFE3000, 0xFF0000):
        lines = []
        for i in range(off, min(off + 0x40, len(raw)), 16):
            lines.append(f'{i:08X}: ' + ' '.join(f'{b:02X}' for b in raw[i:i + 16]))
        previews.append({'offset': f'0x{off:06X}', 'lines': lines})

    payload = {
        'image': 'siti-msd5043-full-16MiB.bin',
        'size': len(raw), 'sha256': digest,
        'byte_counts': {'zero': raw.count(0), 'ff': raw.count(0xFF)},
        'entropy_windows': windows,
        'zero_runs_ge_256': runs(raw, 0),
        'ff_runs_ge_256': runs(raw, 0xFF),
        'string_candidates': strings,
        'signatures': signatures,
        'markers': markers,
        'previews': previews,
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    with PREVIEW.open('w', encoding='utf-8') as f:
        for block in previews:
            f.write(f'### {block["offset"]}\n' + '\n'.join(block['lines']) + '\n\n')
    print(json.dumps({
        'size': len(raw), 'sha256': digest,
        'windows': len(windows), 'zero_runs': len(payload['zero_runs_ge_256']),
        'ff_runs': len(payload['ff_runs_ge_256']), 'strings': len(strings),
        'high_entropy_windows': sum(1 for w in windows if w['class'] == 'HIGH_ENTROPY'),
        'erased_windows': sum(1 for w in windows if w['class'] == 'ERASED_OR_ZERO'),
    }))


if __name__ == '__main__':
    main()
