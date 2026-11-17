#!/usr/bin/env python3
"""Index the candidate resource directory and run bounded format checks."""
import argparse, bz2, collections, csv, ctypes, ctypes.util, gzip, hashlib, json, lzma, math, re, struct, subprocess, zlib
from io import BytesIO
from pathlib import Path
from parse_resource_catalog import parse_catalog, RESOURCE_BASE

SIGS = {
    "png": b"\x89PNG\r\n\x1a\n", "gif87a": b"GIF87a", "gif89a": b"GIF89a",
    "jpeg": b"\xff\xd8\xff", "bmp": b"BM", "mpeg_sequence": b"\x00\x00\x01\xb3",
    "mpeg_pack": b"\x00\x00\x01\xba", "mp3_id3": b"ID3",
    "ogg": b"OggS", "flac": b"fLaC", "riff": b"RIFF", "zip": b"PK\x03\x04",
    "gzip": b"\x1f\x8b", "xz": b"\xfd7zXZ\x00", "bzip2": b"BZh",
    "ttf": b"\x00\x01\x00\x00", "otf": b"OTTO", "woff": b"wOFF",
    "woff2": b"wOF2", "pdf": b"%PDF-", "elf": b"\x7fELF",
}


def _decompress_attempts(blob: bytes, expected: int):
    cap = min(max(expected + 1, 1), 64 * 1024 * 1024)
    results = []
    for name, factory in (("zlib", lambda: zlib.decompressobj(15)),
                          ("gzip", lambda: zlib.decompressobj(31)),
                          ("raw_deflate", lambda: zlib.decompressobj(-15)),
                          ("bzip2", bz2.BZ2Decompressor),
                          ("lzma_auto", lambda: lzma.LZMADecompressor(format=lzma.FORMAT_AUTO))):
        try:
            d = factory()
            if name in ("zlib", "gzip", "raw_deflate"):
                out = d.decompress(blob, cap)
                eof = d.eof
            elif name == "bzip2":
                out = d.decompress(blob, max_length=cap)
                eof = d.eof
            else:
                out = d.decompress(blob, max_length=cap)
                eof = d.eof
            if eof:
                results.append(f"{name}:eof:{len(out)}B:output_match={len(out)==expected}")
        except Exception:
            pass
    return results


def _lz4_attempt(blob: bytes, expected: int):
    libname = ctypes.util.find_library("lz4")
    if not libname or not (0 < expected <= 64 * 1024 * 1024):
        return "unavailable_or_size_out_of_bounds"
    try:
        lib = ctypes.CDLL(libname)
        fn = lib.LZ4_decompress_safe
        fn.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        fn.restype = ctypes.c_int
        out = ctypes.create_string_buffer(expected)
        got = fn(blob, out, len(blob), expected)
        return f"decoded={got}:output_match={got==expected}" if got >= 0 else f"invalid_block:{got}"
    except Exception as exc:
        return "error:" + type(exc).__name__


def _file_hint(blob: bytes):
    try:
        p = subprocess.run(["file", "-b", "-"], input=blob, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=5, check=False)
        return p.stdout.decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def _png_walk(blob: bytes, start: int = 0):
    if start < 0 or start + 8 > len(blob) or not blob.startswith(SIGS["png"], start):
        return {"valid": False, "error": "no_signature", "chunks": []}
    p = start + 8
    chunks = []
    while p + 12 <= len(blob):
        ln = struct.unpack_from(">I", blob, p)[0]
        typ = blob[p + 4:p + 8]
        if ln > 200000 or ln > len(blob) - p - 12:
            return {"valid": False, "error": f"bad_length@{p}", "chunks": chunks}
        data = blob[p + 8:p + 8 + ln]
        crc = struct.unpack_from(">I", blob, p + 8 + ln)[0]
        calc = zlib.crc32(typ + data) & 0xFFFFFFFF
        chunks.append({"type": typ.decode("latin1", "replace"), "length": ln, "crc_ok": calc == crc})
        p += 12 + ln
        if typ == b"IEND":
            return {"valid": True, "chunks": chunks, "end": p, "trailing": len(blob) - p}
    return {"valid": False, "error": "no_iend", "chunks": chunks}


def _pil_check(blob: bytes, start: int = 0):
    if start < 0 or start >= len(blob):
        return "invalid_start"
    try:
        from PIL import Image
    except Exception:
        return "unavailable"
    try:
        im = Image.open(BytesIO(blob[start:]))
        fmt = im.format or ""
        size = im.size
        im.verify()
        try:
            im2 = Image.open(BytesIO(blob[start:]))
            im2.load()
            load = "ok"
        except Exception as exc:
            load = "error:" + type(exc).__name__
        return f"format={fmt};size={size[0]}x{size[1]};verify=ok;load={load}"
    except Exception as exc:
        msg = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", str(exc)[:160].replace("\n", " "))
        return "error:" + type(exc).__name__ + ":" + msg


def _mpeg_check(blob: bytes, start: int = 0):
    if start < 0 or start >= len(blob):
        return "invalid_start"
    data = blob[start:]
    try:
        p = subprocess.run(["ffprobe", "-v", "error", "-f", "mpegvideo", "-show_frames",
                            "-show_streams", "-of", "json", "-i", "pipe:0"], input=data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        try:
            j = json.loads(p.stdout or b"{}")
        except Exception:
            j = {}
        frames = len(j.get("frames", []))
        streams = [{"codec": s.get("codec_name"), "width": s.get("width"), "height": s.get("height")}
                   for s in j.get("streams", [])]
        d = subprocess.run(["ffmpeg", "-v", "error", "-xerror", "-f", "mpegvideo", "-i", "pipe:0",
                            "-map", "0:v:0", "-f", "null", "-"], input=data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        err = (p.stderr + b" " + d.stderr).decode("utf-8", "replace").replace("\n", " ").strip()[:200]
        err = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", err)
        return (f"probe_exit={p.returncode};frames={frames};streams={json.dumps(streams, separators=(',', ':'))};"
                f"decode_exit={d.returncode};stderr={err}")
    except Exception as exc:
        return "error:" + type(exc).__name__


def _bmp_header_valid_at(blob: bytes, q: int):
    if q < 0 or q + 54 > len(blob) or blob[q:q + 2] != b"BM":
        return False
    try:
        _, fsize, _, _, pixel_off = struct.unpack_from("<2sIHHI", blob, q)
        dib = struct.unpack_from("<I", blob, q + 14)[0]
        w, h = struct.unpack_from("<ii", blob, q + 18)
        planes, bpp = struct.unpack_from("<HH", blob, q + 26)
        return (fsize >= 54 and fsize <= len(blob) - q and dib >= 40 and 0 < w < 10000 and
                0 < abs(h) < 10000 and planes == 1 and bpp in (1, 4, 8, 16, 24, 32) and
                14 + dib <= len(blob) - q and pixel_off < fsize)
    except struct.error:
        return False


def analyze_payload(blob: bytes, name: str, expected: int):
    if not blob or all(x == 0 for x in blob):
        content = "all_zero"
    elif all(x == 0xFF for x in blob):
        content = "all_ff"
    else:
        content = "mixed"
    counts = collections.Counter(blob)
    entropy = -sum((n / len(blob)) * math.log2(n / len(blob)) for n in counts.values()) if blob else 0.0
    start_matches = [kind for kind, sig in SIGS.items() if blob.startswith(sig)]
    near_start_matches = [kind for kind, sig in SIGS.items() if blob[1:].startswith(sig)]
    interior = []
    for kind, sig in SIGS.items():
        pos = blob.find(sig)
        if pos > 0:
            interior.append(f"{kind}@0x{pos:X}")
    bmp_positions = [m.start() for m in re.finditer(b"BM", blob)]
    bmp_valid_positions = [q for q in bmp_positions if _bmp_header_valid_at(blob, q)]
    bmp_at_0 = _bmp_header_valid_at(blob, 0)
    bmp_at_1 = _bmp_header_valid_at(blob, 1)
    png_at_0 = _png_walk(blob, 0)
    png_at_1 = _png_walk(blob, 1)
    pil_at_0 = _pil_check(blob, 0)
    pil_at_1 = _pil_check(blob, 1)
    ext = Path(name).suffix.lower()
    mpeg_at_0 = _mpeg_check(blob, 0) if ext == ".mpg" else "not_applicable"
    mpeg_at_1 = _mpeg_check(blob, 1) if ext == ".mpg" else "not_applicable"
    mpeg_valid = False
    for result in (mpeg_at_0, mpeg_at_1):
        if result != "not_applicable" and "frames=0" not in result and "decode_exit=0" in result:
            mpeg_valid = True
    pil_valid = any(x.startswith("format=") and "verify=ok" in x and "load=ok" in x
                    for x in (pil_at_0, pil_at_1))
    std = _decompress_attempts(blob, expected)
    lz4 = _lz4_attempt(blob, expected)
    decoder_match = any("output_match=True" in result for result in std) or "output_match=True" in lz4
    validated = png_at_0["valid"] or png_at_1["valid"] or bmp_at_0 or bmp_at_1 or pil_valid or mpeg_valid
    if content == "all_zero":
        classification = "zero_filled_range_no_media_payload"
    elif validated or decoder_match:
        classification = "decoded_or_structurally_validated"
    elif start_matches or near_start_matches:
        classification = "signature_candidate_requires_structural_validation"
    else:
        classification = "opaque_mixed_no_validated_common_format"
    embedded_parsers = []
    embedded_parsers.append(f"bmp_magic_candidates={sum(q > 0 for q in bmp_positions)}:"
                            f"valid_offsets={','.join(hex(q) for q in bmp_valid_positions if q > 0)}")
    q = blob.find(SIGS["ttf"])
    if q >= 0:
        if q + 12 <= len(blob):
            _, ntables = struct.unpack_from(">IH", blob, q)
            if 0 < ntables <= 256 and q + 12 + ntables * 16 <= len(blob):
                bounds = True
                for j in range(ntables):
                    _, _, off, size = struct.unpack_from(">4sIII", blob, q + 12 + j * 16)
                    bounds &= off <= len(blob) - q and size <= len(blob) - q - off
                embedded_parsers.append(f"sfnt@0x{q:X}:candidate_tables={ntables}:bounds={bounds}")
            else:
                embedded_parsers.append(f"sfnt@0x{q:X}:invalid_table_count={ntables}")
        else:
            embedded_parsers.append(f"sfnt@0x{q:X}:truncated_header")
    for q in [m.start() for m in re.finditer(re.escape(SIGS["gzip"]), blob)]:
        try:
            d = zlib.decompressobj(31); out = d.decompress(blob[q:], min(max(expected + 1, 1), 64 * 1024 * 1024))
            embedded_parsers.append(f"gzip@0x{q:X}:eof={d.eof}:decoded={len(out)}")
        except Exception:
            embedded_parsers.append(f"gzip@0x{q:X}:invalid")
    wrapper = []
    if near_start_matches:
        wrapper.append(f"signature_at_offset_1={';'.join(near_start_matches)};prefix=0x{blob[0]:02X}")
    if ext == ".bmp" and len(blob) >= 6 and blob[1:3] == b"BM":
        embedded = int.from_bytes(blob[3:6], "little")
        wrapper.append(f"bmp_embedded_u24={embedded};matches_output={embedded == expected}")
    wrapper.append(f"stored_minus_output={len(blob) - expected}")
    return {
        "content_class": content, "entropy_bits_per_byte": f"{entropy:.6f}",
        "signature_at_start": ";".join(start_matches),
        "signature_at_offset_1": ";".join(near_start_matches),
        "signature_offset": 1 if near_start_matches else (0 if start_matches else ""),
        "prefix_hex": f"0x{blob[0]:02X}" if blob else "",
        "interior_signature_candidates": ";".join(interior),
        "interior_parser_results": ";".join(embedded_parsers),
        "strict_bmp_header_valid": bmp_at_0 or bmp_at_1,
        "bmp_header_valid_at_0": bmp_at_0, "bmp_header_valid_at_1": bmp_at_1,
        "png_chunk_walk_at_0": json.dumps(png_at_0, separators=(",", ":")),
        "png_chunk_walk_at_1": json.dumps(png_at_1, separators=(",", ":")),
        "pil_check_at_0": pil_at_0, "pil_check_at_1": pil_at_1,
        "interior_bmp_magic_count": sum(q > 0 for q in bmp_positions),
        "interior_bmp_valid_offsets": ";".join(hex(q) for q in bmp_valid_positions if q > 0),
        "stdlib_decoder_successes": ";".join(std),
        "lz4_raw_block_result": lz4,
        "libmagic_hint": _file_hint(blob),
        "mpeg_probe_at_0": mpeg_at_0, "mpeg_probe_at_1": mpeg_at_1,
        "wrapper_observation": ";".join(wrapper),
        "classification": classification,
    }


def build(data: bytes, start=0x650018, count=281, base=RESOURCE_BASE):
    entries = parse_catalog(data, start=start, count=count, base=base)
    index_rows, format_rows = [], []
    for e in entries:
        name = e["filename_candidate"]
        relative = e["payload_offset_relative_candidate"]
        offset = e["payload_offset_absolute_candidate"]
        size = e["field_04_u32le_candidate"]
        inbounds = e["candidate_range_in_image"]
        blob = data[offset:offset + size] if inbounds else b""
        digest = hashlib.sha256(blob).hexdigest() if inbounds else ""
        name_state = "printable_name" if e["filename_candidate_valid_printable"] else "unlabelled_or_malformed"
        index_rows.append({
            "slot_index": e["index"], "catalog_offset": f"0x{e['catalog_offset']:X}",
            "raw_slot_hex": e["raw_hex"],
            "field_00_relative_offset_candidate": f"0x{relative:X}",
            "field_00_absolute_offset_candidate": f"0x{offset:X}",
            "field_04_stored_length_candidate": size,
            "field_08_output_length_candidate": e["field_08_u32le_candidate"],
            "field_0c_flags_candidate": f"0x{e['field_0c_u32le_candidate']:X}",
            "filename_candidate": name, "name_state": name_state,
            "payload_range_in_bounds": inbounds, "payload_sha256": digest,
            "payload_all_zero": bool(inbounds and blob and not any(blob)),
        })
        if not e["filename_candidate_valid_printable"] or not inbounds:
            continue
        fmt = analyze_payload(blob, name, e["field_08_u32le_candidate"])
        ext = Path(name).suffix.lower()
        expected_kind = {".gam": "proprietary graphics candidate", ".png": "PNG-labelled candidate",
                         ".bmp": "BMP-labelled candidate", ".gif": "GIF-labelled candidate",
                         ".mpg": "MPEG-labelled candidate"}.get(ext, "unclassified extension")
        format_rows.append({
            "slot_index": e["index"], "filename": name, "filename_extension": ext,
            "declared_type_candidate": expected_kind,
            "payload_offset_relative": f"0x{relative:X}",
            "payload_offset_absolute": f"0x{offset:X}",
            "stored_length": size, "output_length_candidate": e["field_08_u32le_candidate"],
            "flags_candidate": f"0x{e['field_0c_u32le_candidate']:X}",
            "payload_sha256": digest, **fmt,
        })
    return index_rows, format_rows


def _write(path: Path, rows):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else [])
        if rows:
            w.writeheader(); w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x650018)
    ap.add_argument("--count", type=int, default=281)
    ap.add_argument("--base", type=lambda x: int(x, 0), default=RESOURCE_BASE)
    a = ap.parse_args()
    data = a.image.read_bytes()
    idx, fmts = build(data, a.start, a.count, a.base)
    a.output.mkdir(parents=True, exist_ok=True)
    _write(a.output / "resource-index.csv", idx)
    _write(a.output / "resource-formats.csv", fmts)
    anomalies = []

    def add_anomaly(aid, table_off, raw, name, poff, plen, kind, confidence):
        payload = data[poff:poff + plen] if poff + plen <= len(data) else b""
        anomalies.append({"anomaly_id": aid, "catalog_or_data_offset": f"0x{table_off:X}",
                          "raw_or_range_length": len(raw) if raw else plen,
                          "raw_hex": raw.hex() if isinstance(raw, bytes) else "",
                          "name_candidate": name, "payload_offset": f"0x{poff:X}",
                          "payload_length": plen,
                          "payload_sha256": hashlib.sha256(payload).hexdigest() if len(payload) == plen else "",
                          "payload_all_zero": bool(payload) and not any(payload),
                          "description": kind, "confidence": confidence})
    add_anomaly("ROW-210", 0x652778, data[0x652778:0x6527A8], "llup.gam suffix only",
                0x650000 + 0x106C12, 0x3B,
                "Fixed slot has relative offset 0x106C12 and length 0x3B; its +0x08/+0x0C fields contain the ASCII bytes 'llup.gam'. Corrected payload at 0x756C12 is populated and begins with the same FF 06 00 4F 44 header seen in .gam payloads. The true name is likely ns_scrollup.gam but remains UNKNOWN.",
                "PARTIAL DESCRIPTOR; PAYLOAD POPULATED")
    add_anomaly("UNALIGNED-NS-SIDER", 0x652799, data[0x652799:0x6527C9], "ns_sider.gam",
                0x650000 + 0x106D49, 0x42,
                "Unaligned 48-byte descriptor fields are 0x106D49/0x42/0x60/1. Corrected payload at 0x756D49 is populated and begins with FF 06 00 4F 44.",
                "CONFIRMED descriptor bytes; payload populated")
    add_anomaly("UNALIGNED-NS-SILINCE", 0x6527C9, data[0x6527C9:0x6527F9], "ns_silince.gam",
                0x650000 + 0x106D8B, 0x799,
                "Unaligned 48-byte descriptor fields are 0x106D8B/0x799/0xD98/1. Corrected payload at 0x756D8B is populated. Aligned slot 213 at 0x652808 duplicates this descriptor.",
                "CONFIRMED duplicate bytes; payload populated")
    add_anomaly("RETRACTED-ZERO-GAP", 0x650000 + 0x106C4D, b"", "", 0x650000 + 0x106C4D, 0xFC,
                "The previous zero-filled interval claim used relative offsets as absolute. With base 0x650000 the interval is populated; the zero-gap interpretation is RETRACTED.",
                "RETRACTED")
    _write(a.output / "resource-anomalies.csv", anomalies)
    summary = {"base": hex(a.base), "directory_slots": len(idx), "named_payload_rows": len(fmts),
               "zero_payload_rows": sum(r["payload_all_zero"] for r in idx),
               "content_classes": dict(collections.Counter(r["content_class"] for r in fmts)),
               "classifications": dict(collections.Counter(r["classification"] for r in fmts)),
               "start_signatures": dict(collections.Counter(r["signature_at_start"] or "none" for r in fmts)),
               "signature_at_offset_1": dict(collections.Counter(r["signature_at_offset_1"] or "none" for r in fmts)),
               "field_0c_flags": dict(collections.Counter(r["flags_candidate"] for r in fmts))}
    (a.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
