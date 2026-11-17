#!/usr/bin/env python3
"""Analyze aligned MStar-style info records, sector spans, differences and candidate fields."""
from __future__ import annotations
import argparse,bz2,csv,hashlib,json,lzma,math,struct,zlib
from collections import defaultdict
from pathlib import Path

SECTOR=0x10000
SECTOR_BASES=(0xFE0000,0xFF0000)
INFO_NAMES=(b"Loader Info\0",b"Update Info\0",b"System Info\0")
EXTRA_OFFSET=0x3000
EXTRA_LENGTH=0x808

def sha256(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def category(value:int)->str:return "zero" if value==0 else "erased_ff" if value==255 else "populated"
def class_runs(data:bytes):
    out=[];start=0
    while start<len(data):
        kind=category(data[start]);end=start+1
        while end<len(data) and category(data[end])==kind:end+=1
        out.append((start,end,kind));start=end
    return out
def diff_runs(a:bytes,b:bytes):
    out=[];i=0
    while i<len(a):
        if a[i]==b[i]:i+=1;continue
        j=i+1
        while j<len(a) and a[j]!=b[j]:j+=1
        out.append((i,j));i=j
    return out

def entropy(data:bytes)->float:
    if not data:return 0.0
    counts=[0]*256
    for x in data:counts[x]+=1
    return -sum((n/len(data))*math.log2(n/len(data)) for n in counts if n)
def decoder_probes(data:bytes):
    candidates={"prefix_plus_0x800_body":data[4:0x804],"prefix_plus_body_and_tail":data[4:],"whole_span":data}
    out=[];cap=1_000_000
    for boundary,chunk in candidates.items():
        funcs=[("zlib",lambda:zlib.decompressobj(15)),("gzip",lambda:zlib.decompressobj(31)),("raw_deflate",lambda:zlib.decompressobj(-15))]
        for label,factory in funcs:
            try:
                d=factory();result=d.decompress(chunk,cap);eof=d.eof
                out.append({"decoder":label,"boundary":boundary,"valid_end_marker":eof,"output_length":len(result),"output_sha256":sha256(result),"truncated_at_1MiB":len(result)>=cap})
            except Exception as e:out.append({"decoder":label,"boundary":boundary,"error":type(e).__name__})
        try:
            d=bz2.BZ2Decompressor();result=d.decompress(chunk,max_length=cap);out.append({"decoder":"bzip2","boundary":boundary,"valid_end_marker":d.eof,"output_length":len(result),"output_sha256":sha256(result),"truncated_at_1MiB":len(result)>=cap})
        except Exception as e:out.append({"decoder":"bzip2","boundary":boundary,"error":type(e).__name__})
        for label,fmt in (("lzma_auto",lzma.FORMAT_AUTO),("lzma_alone",lzma.FORMAT_ALONE)):
            try:
                d=lzma.LZMADecompressor(format=fmt);result=d.decompress(chunk,max_length=cap);out.append({"decoder":label,"boundary":boundary,"valid_end_marker":d.eof,"output_length":len(result),"output_sha256":sha256(result),"truncated_at_1MiB":len(result)>=cap})
            except Exception as e:out.append({"decoder":label,"boundary":boundary,"error":type(e).__name__})
    return out

def crc32c(data:bytes)->int:
    crc=0xffffffff
    for value in data:
        crc^=value
        for _ in range(8):crc=(crc>>1)^(0x82f63b78 if crc&1 else 0)
    return crc^0xffffffff
def crc32_mpeg2(data:bytes,final_xor:int=0)->int:
    crc=0xffffffff
    for value in data:
        crc^=value<<24
        for _ in range(8):crc=((crc<<1)&0xffffffff)^(0x04c11db7 if crc&0x80000000 else 0)
    return crc^final_xor
def crc16_ccitt(data:bytes)->int:
    crc=0xffff
    for value in data:
        crc^=value<<8
        for _ in range(8):crc=((crc<<1)&0xffff)^(0x1021 if crc&0x8000 else 0)
    return crc

def crc_trials(record:bytes):
    if len(record)<20:return {"stored_hex":"","trials":[],"matches":[]}
    trailer=record[-4:];stored_le=int.from_bytes(trailer,"little");stored_be=int.from_bytes(trailer,"big")
    funcs={"CRC-32/ISO-HDLC":lambda d:zlib.crc32(d)&0xffffffff,
      "CRC-32C":crc32c,"CRC-32/MPEG-2":lambda d:crc32_mpeg2(d,0),
      "CRC-32/BZIP2":lambda d:crc32_mpeg2(d,0xffffffff)}
    boundaries=(("whole_record_before_trailer",record[:-4]),
      ("after_length_before_trailer",record[12:-4]),
      ("body_before_trailer",record[16:-4]))
    trials=[];matches=[]
    for alg,fn in funcs.items():
        for label,chunk in boundaries:
            value=fn(chunk);trial={"algorithm":alg,"boundary":label,"computed_hex":f"0x{value:08X}","stored_le_match":value==stored_le,"stored_be_match":value==stored_be}
            trials.append(trial)
            if trial["stored_le_match"] or trial["stored_be_match"]:matches.append(trial)
    for label,chunk in boundaries:
        value=crc16_ccitt(chunk)
        trial={"algorithm":"CRC-16/CCITT-FALSE","boundary":label,"computed_hex":f"0x{value:04X}",
          "stored_low16_match":value in (stored_le&0xffff,stored_be&0xffff),
          "stored_high16_match":value in (stored_le>>16,stored_be>>16)}
        trials.append(trial)
        if trial["stored_low16_match"] or trial["stored_high16_match"]:matches.append(trial)
    return {"stored_hex":trailer.hex(),"stored_le":f"0x{stored_le:08X}","stored_be":f"0x{stored_be:08X}","trials":trials,"matches":matches}

def find_all(data:bytes,needle:bytes):
    hits=[];pos=0
    while True:
        pos=data.find(needle,pos)
        if pos<0:return hits
        hits.append(pos);pos+=1

def analyze(data:bytes):
    if len(data)<max(SECTOR_BASES)+SECTOR:raise ValueError("input image does not contain both 64 KiB sectors")
    sectors={base:data[base:base+SECTOR] for base in SECTOR_BASES}
    records=[]
    for base,sector in sectors.items():
        for marker in INFO_NAMES:
            for rel in find_all(sector[:0x3000],marker):
                if rel+16>len(sector):continue
                le_len=int.from_bytes(sector[rel+12:rel+16],"little")
                be_len=int.from_bytes(sector[rel+12:rel+16],"big")
                end=rel+16+le_len
                bounded=(le_len>0 and end<=len(sector))
                raw=sector[rel:end] if bounded else b""
                name=marker[:-1].decode("ascii")
                records.append({"sector_base":base,"sector_name":"FE" if base==0xFE0000 else "FF","record_name":name,
                  "relative_offset":rel,"image_offset":base+rel,"length_field_offset":rel+12,
                  "length_le":le_len,"length_be":be_len,"declared_record_size_le":16+le_len,
                  "bounded_record_end_relative":end if bounded else None,"bounded_record_size_matches":bounded,
                  "record_sha256":sha256(raw) if raw else "",
                  "crc_analysis":crc_trials(raw) if raw else {"matches":[],"trials":[]}})
    by_key={(r["sector_base"],r["record_name"]):r for r in records}
    extra=data[0xFE0000+EXTRA_OFFSET:0xFE0000+EXTRA_OFFSET+EXTRA_LENGTH]
    if len(extra)!=EXTRA_LENGTH:raise ValueError("additional populated span is truncated")
    extra_len=int.from_bytes(extra[:4],"little")
    extra_tail=extra[-4:]
    extra_trials=[]
    funcs={"CRC-32/ISO-HDLC":lambda d:zlib.crc32(d)&0xffffffff,"CRC-32C":crc32c,
      "CRC-32/MPEG-2":lambda d:crc32_mpeg2(d,0),"CRC-32/BZIP2":lambda d:crc32_mpeg2(d,0xffffffff)}
    spans=(("whole_minus_tail",extra[:-4]),("after_length_minus_tail",extra[4:-4]),
      ("body_including_tail",extra[4:]),("whole_span",extra))
    stored_le=int.from_bytes(extra_tail,"little");stored_be=int.from_bytes(extra_tail,"big")
    for alg,fn in funcs.items():
        for label,chunk in spans:
            val=fn(chunk);extra_trials.append({"algorithm":alg,"boundary":label,"computed_hex":f"0x{val:08X}","stored_le_match":val==stored_le,"stored_be_match":val==stored_be})
    for label,chunk in spans:
        val=crc16_ccitt(chunk)
        extra_trials.append({"algorithm":"CRC-16/CCITT-FALSE","boundary":label,"computed_hex":f"0x{val:04X}","stored_low16_match":val in (stored_le&0xffff,stored_be&0xffff),"stored_high16_match":val in (stored_le>>16,stored_be>>16)})
    a=sectors[0xFE0000];b=sectors[0xFF0000]
    differences=diff_runs(a,b)
    spans_by_sector={}
    for base,sector in sectors.items():
        spans_by_sector[base]=[{"start_relative":s,"end_relative_exclusive":e,"length":e-s,"class":c} for s,e,c in class_runs(sector)]
    marker_hits={m[:-1].decode("ascii"):find_all(data,m) for m in INFO_NAMES}
    value_refs=[];seen=set()
    for r in records:
        if not r["record_sha256"]:continue
        raw=data[r["image_offset"]:r["image_offset"]+r["declared_record_size_le"]]
        for off in range(12,len(raw)-3,4):
            if r["record_name"]=="System Info" and 16<=off<0x24:continue
            value=int.from_bytes(raw[off:off+4],"little")
            if not value or value==0xffffffff or value in seen:continue
            seen.add(value);needle=value.to_bytes(4,"little");hits=find_all(data,needle)
            value_refs.append({"value_le":f"0x{value:08X}","decimal":value,"record_name":r["record_name"],
              "field_relative_offset":off,"record_sector":r["sector_name"],"occurrences":len(hits),
              "occurrence_offsets":[f"0x{x:X}" for x in hits[:16]],"truncated":len(hits)>16})
    update=by_key.get((0xFE0000,"Update Info"));updates={}
    if update and update["record_sha256"]:
        raw=data[update["image_offset"]:update["image_offset"]+update["declared_record_size_le"]]
        freq=int.from_bytes(raw[0x14:0x18],"little");sr=int.from_bytes(raw[0x18:0x1c],"little")
        matches=[]
        for i in range(100):
            o=0x800018+i*64
            if o+0x1a<=len(data):
                f=int.from_bytes(data[o+0x10:o+0x14],"little");s=int.from_bytes(data[o+0x18:o+0x1a],"little")
                if f==freq and s==sr:matches.append({"xpdr_row_index":i,"xpdr_id_candidate":int.from_bytes(data[o+8:o+10],"little"),"frequency_candidate":f,"symbol_rate_candidate":s})
        updates={"record_frequency_u32_le_candidate":freq,"record_symbol_rate_u32_le_candidate":sr,"matching_xpdr_rows":matches}
    return {"input_size":len(data),"input_sha256":sha256(data),"sector_size":SECTOR,
      "sectors":[{"base":base,"sector_name":"FE" if base==0xFE0000 else "FF","sha256":sha256(sectors[base]),
        "prefix_0x3000_sha256":sha256(sectors[base][:0x3000]),"class_run_counts":{k:sum(x["class"]==k for x in spans_by_sector[base]) for k in ("zero","erased_ff","populated")},
        "class_byte_counts":{k:sum(x["length"] for x in spans_by_sector[base] if x["class"]==k) for k in ("zero","erased_ff","populated")}} for base in SECTOR_BASES],
      "records":records,"marker_hits":{k:[f"0x{x:X}" for x in v] for k,v in marker_hits.items()},
      "sector_spans":{f"0x{k:X}":v for k,v in spans_by_sector.items()},
      "difference_ranges":[{"start_relative":s,"end_relative_exclusive":e,"length":e-s,"image_offset_fe":0xFE0000+s,"image_offset_ff":0xFF0000+s,"different_bytes":e-s} for s,e in differences],
      "different_byte_count":sum(e-s for s,e in differences),"common_prefix_0x3000":a[:0x3000]==b[:0x3000],
      "extra_span":{"image_offset":0xFE0000+EXTRA_OFFSET,"length":EXTRA_LENGTH,"sha256":sha256(extra),
        "length_word_le":extra_len,"length_equals_span":extra_len==EXTRA_LENGTH,
        "class_counts":{k:sum(category(x)==k for x in extra) for k in ("zero","erased_ff","populated")},
        "entropy_bits_per_byte":entropy(extra),"tail_hex":extra_tail.hex(),"tail_u32_le":stored_le,"crc_trials":extra_trials,
        "decompression_probes":decoder_probes(extra)},
      "field_value_references":value_refs,"update_info_xpdr_cross_reference":updates}

def write_outputs(result,data:bytes,out:Path,evidence_dir:Path|None=None):
    out.mkdir(parents=True,exist_ok=True)
    (out/"loader-info-summary.json").write_text(json.dumps(result,indent=2)+"\n")
    with (out/"loader-info-sectors.csv").open("w",newline="") as f:
        fields=["sector_name","sector_base","sha256","prefix_0x3000_sha256","class_run_counts","class_byte_counts"]
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in result["sectors"]:w.writerow({"sector_name":r["sector_name"],"sector_base":f"0x{r["base"]:X}","sha256":r["sha256"],"prefix_0x3000_sha256":r["prefix_0x3000_sha256"],"class_run_counts":json.dumps(r["class_run_counts"],sort_keys=True),"class_byte_counts":json.dumps(r["class_byte_counts"],sort_keys=True)})
    with (out/"loader-sector-spans.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["sector_base","sector_name","start_relative","end_relative_exclusive","length","class"]);w.writeheader()
        for base,rows in result["sector_spans"].items():
            for row in rows:w.writerow({"sector_base":base,"sector_name":"FE" if int(base,16)==0xFE0000 else "FF",**row})
    with (out/"loader-sector-diff-ranges.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["range_id","start_relative","end_relative_exclusive","length","image_offset_fe","image_offset_ff","different_bytes"]);w.writeheader()
        for i,r in enumerate(result["difference_ranges"],1):w.writerow({"range_id":i,**r})
    if evidence_dir is None:return
    evidence_dir.mkdir(parents=True,exist_ok=True)
    for base in SECTOR_BASES:
        name="FE0000" if base==0xFE0000 else "FF0000"
        (evidence_dir/f"loader-sector-{name}.bin").write_bytes(data[base:base+SECTOR])
    (evidence_dir/"loader-common-prefix-0x3000.bin").write_bytes(data[0xFE0000:0xFE3000])
    with (evidence_dir/"loader-sector-comparison.csv").open("w",newline="") as f:
        fields=["range_id","sector_relative_offset","image_offset_fe","image_offset_ff","fe_byte_hex","ff_byte_hex"]
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for rid,r in enumerate(result["difference_ranges"],1):
            for rel in range(r["start_relative"],r["end_relative_exclusive"]):
                w.writerow({"range_id":rid,"sector_relative_offset":f"0x{rel:04X}","image_offset_fe":f"0x{0xFE0000+rel:06X}","image_offset_ff":f"0x{0xFF0000+rel:06X}","fe_byte_hex":f"{data[0xFE0000+rel]:02X}","ff_byte_hex":f"{data[0xFF0000+rel]:02X}"})
    with (evidence_dir/"loader-fields.csv").open("w",newline="") as f:
        fields=["source_region","record_name","record_image_offset","record_relative_offset","field_relative_offset","field_image_offset","width_bits","raw_hex","u16_le_hex","u16_le_decimal","u16_be_hex","u16_be_decimal","u32_le_hex","u32_le_decimal","u32_be_hex","u32_be_decimal","candidate_note"]
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in result["records"]:
            if not r["record_sha256"]:continue
            raw=data[r["image_offset"]:r["image_offset"]+r["declared_record_size_le"]];base=r["image_offset"];rel=r["relative_offset"]
            for width in (2,4):
                for off in range(12,len(raw)-width+1,width):
                    piece=raw[off:off+width];le=int.from_bytes(piece,"little");be=int.from_bytes(piece,"big")
                    row={"source_region":r["sector_name"],"record_name":r["record_name"],"record_image_offset":f"0x{base:X}","record_relative_offset":f"0x{rel:X}","field_relative_offset":f"0x{off:X}","field_image_offset":f"0x{base+off:X}","width_bits":width*8,"raw_hex":piece.hex(),"candidate_note":"numeric interpretation only; semantics unassigned"}
                    if width==2:row.update({"u16_le_hex":f"0x{le:04X}","u16_le_decimal":le,"u16_be_hex":f"0x{be:04X}","u16_be_decimal":be})
                    else:row.update({"u32_le_hex":f"0x{le:08X}","u32_le_decimal":le,"u32_be_hex":f"0x{be:08X}","u32_be_decimal":be})
                    w.writerow(row)
        # Preserve numeric candidates at both ends of the FE-only 0x808-byte span.
        base=0xFE0000+EXTRA_OFFSET;span=data[base:base+EXTRA_LENGTH]
        for width in (2,4):
            offsets=sorted(set(list(range(0,min(16,EXTRA_LENGTH-width+1),width))+list(range(max(0,EXTRA_LENGTH-16),EXTRA_LENGTH-width+1,width))))
            for off in offsets:
                piece=span[off:off+width];le=int.from_bytes(piece,"little");be=int.from_bytes(piece,"big")
                row={"source_region":"FE","record_name":"FE-only 0x808 span boundary sample","record_image_offset":f"0x{base:X}","record_relative_offset":f"0x{EXTRA_OFFSET:X}","field_relative_offset":f"0x{off:X}","field_image_offset":f"0x{base+off:X}","width_bits":width*8,"raw_hex":piece.hex(),"candidate_note":"boundary sample only; block body remains UNKNOWN"}
                if width==2:row.update({"u16_le_hex":f"0x{le:04X}","u16_le_decimal":le,"u16_be_hex":f"0x{be:04X}","u16_be_decimal":be})
                else:row.update({"u32_le_hex":f"0x{le:08X}","u32_le_decimal":le,"u32_be_hex":f"0x{be:08X}","u32_be_decimal":be})
                w.writerow(row)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("image",type=Path);p.add_argument("--output",type=Path,required=True);p.add_argument("--evidence-dir",type=Path);a=p.parse_args()
    data=a.image.read_bytes();result=analyze(data);write_outputs(result,data,a.output,a.evidence_dir)
    print(json.dumps({"input_sha256":result["input_sha256"],"markers":result["marker_hits"],"different_bytes":result["different_byte_count"],"ranges":result["difference_ranges"],"output":str(a.output),"private_evidence":str(a.evidence_dir) if a.evidence_dir else None},indent=2))
if __name__=="__main__":main()
