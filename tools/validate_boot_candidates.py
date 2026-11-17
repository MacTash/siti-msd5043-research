#!/usr/bin/env python3
"""Validate bounded boot/container candidates without executing firmware."""
import argparse, csv, hashlib, json, lzma, struct
from pathlib import Path

CANDIDATES = {
 "JBOOT?@0x35A3": (0x35A3, "signature-only Binwalk candidate"),
 "JBOOT?@0x15C4FF": (0x15C4FF, "signature-only Binwalk candidate"),
 "JBOOT?@0x6393D8": (0x6393D8, "signature-only Binwalk candidate"),
 "JBOOT?@0x717590": (0x717590, "signature-only Binwalk candidate"),
 "JBOOT?@0x978057": (0x978057, "signature-only Binwalk candidate"),
 "LZMA?@0x928EB5": (0x928EB5, "Binwalk property/dictionary candidate"),
 "ESP32?@0x8004A9": (0x8004A9, "ESP image magic candidate"),
 "ESP32?@0x8149C6": (0x8149C6, "ESP image magic candidate"),
 "ESP32?@0x8283D6": (0x8283D6, "ESP image magic candidate"),
 "ESP32?@0x8704A9": (0x8704A9, "exact +0x70000 mirror candidate"),
 "ESP32?@0x8849C6": (0x8849C6, "exact +0x70000 mirror candidate"),
 "ESP32?@0x8983D6": (0x8983D6, "exact +0x70000 mirror candidate"),
}
def sha(b): return hashlib.sha256(b).hexdigest()
def validate_esp(blob, off):
    if blob[off:off+1] != b"\xe9": return {"valid":False,"reason":"missing E9 image magic"}
    count=blob[off+1]; mode=blob[off+2]; sizefreq=blob[off+3]
    entry=int.from_bytes(blob[off+4:off+8],"little")
    pos=off+8; segments=[]; errors=[]
    for i in range(count):
        if pos+8>len(blob): errors.append("segment header outside image"); break
        addr,n=int.from_bytes(blob[pos:pos+4],"little"),int.from_bytes(blob[pos+4:pos+8],"little")
        pos+=8
        if n==0: errors.append(f"segment {i} has zero length")
        if n>64*1024*1024: errors.append(f"segment {i} exceeds safe 64 MiB limit"); break
        if pos+n>len(blob): errors.append(f"segment {i} data exceeds image"); break
        segments.append({"index":i,"load_address":f"0x{addr:08X}","length":n,"data_offset":f"0x{pos:X}"})
        pos+=n
    return {"valid":not errors and len(segments)==count,"magic":"E9","segment_count":count,"spi_mode":mode,"flash_size_frequency":sizefreq,"entry_address":f"0x{entry:08X}","segments":segments,"post_segment_header_offset":f"0x{pos:X}","errors":errors}
def validate_lzma_alone(src):
    header={"header_hex":src[:13].hex(),"property_byte":src[0],"dictionary_le":int.from_bytes(src[1:5],"little"),"uncompressed_size_le":int.from_bytes(src[5:13],"little")}
    try:
        d=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        out=d.decompress(src,max_length=32*1024*1024)
        used=len(src)-len(d.unused_data)
        header.update({"decoder_eof":d.eof,"bounded_stream_length":used,"output_length":len(out),"output_sha256":sha(out),"output_all_zero":bool(out) and not any(out),"trailing_bytes":len(d.unused_data)})
        return d.eof and len(out)==header["uncompressed_size_le"],header,out
    except Exception as e:
        header.update({"decoder_error":type(e).__name__,"error":str(e)[:140]})
        return False,header,b""
def analyze(path, extract_dir=None):
    b=path.read_bytes()
    if len(b)!=0x1000000: raise ValueError("expected 16 MiB image")
    rows=[]
    for name,(off,note) in CANDIDATES.items():
        row={"candidate":name,"offset":f"0x{off:X}","assessment":note,"available_bytes":len(b)-off,"validated":False,"details":""}
        if name.startswith("ESP32"):
            v=validate_esp(b,off);row["details"]=json.dumps(v,separators=(",",":"));row["validated"]=v["valid"]
        elif name.startswith("LZMA"):
            valid,result,out=validate_lzma_alone(b[off:])
            row["validated"]=valid
            if valid:
                result["stream_end_offset"]=f"0x{off+result['bounded_stream_length']:X}"
                if extract_dir:
                    extract_dir.mkdir(parents=True,exist_ok=True)
                    target=extract_dir/"lzma-928eb5.decoded.bin";target.write_bytes(out)
                    result["extracted_private_artifact"]=target.name
            row["details"]=json.dumps(result,separators=(",",":"))
        else:
            row["details"]="Reported size exceeds image boundary; header/signature and checksum have not validated."
        rows.append(row)
    diagnostics={"image_size":len(b),"image_sha256":sha(b),"elf_magic_offsets":[],"mstar_b007_offsets":[],"mstar_bead_de_offsets":[],"mstar_efadde_offsets":[]}
    for name,needle in [("elf_magic_offsets",b"\x7fELF"),("mstar_b007_offsets",b"\x00\x00\xb0\x07"),("mstar_bead_de_offsets",b"\xbe\xad\xde"),("mstar_efadde_offsets",b"\xef\xad\xde")]:
        hits=[];p=0
        while (p:=b.find(needle,p))>=0: hits.append(f"0x{p:X}");p+=1
        diagnostics[name]=hits[:32]
    return rows,diagnostics
def main():
    p=argparse.ArgumentParser();p.add_argument("image",type=Path);p.add_argument("--csv",type=Path,required=True);p.add_argument("--json",type=Path,required=True);p.add_argument("--extract-dir",type=Path);a=p.parse_args()
    rows,diag=analyze(a.image,a.extract_dir);a.csv.parent.mkdir(parents=True,exist_ok=True);a.json.parent.mkdir(parents=True,exist_ok=True)
    with a.csv.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["candidate","offset","assessment","available_bytes","validated","details"]);w.writeheader();w.writerows(rows)
    a.json.write_text(json.dumps(diag,indent=2)+"\n")
    print(json.dumps({"image_sha256":diag["image_sha256"],"candidates":len(rows),"validated_candidates":[r["candidate"] for r in rows if r["validated"]],"diagnostics":diag},indent=2))
if __name__=="__main__":main()
