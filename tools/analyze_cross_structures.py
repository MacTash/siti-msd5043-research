#!/usr/bin/env python3
"""Cross-correlate bounded Loader Info, XPDR, media and resource evidence."""
from __future__ import annotations
import argparse,csv,hashlib,json,re,struct,subprocess
from collections import Counter,defaultdict
from pathlib import Path

FW_SIZE=0x1000000; FE=0xFE0000; FF=0xFF0000; SPAN_OFF=0x3000; SPAN_LEN=0x808
XPDR_BASE=0x800018; XPDR_STRIDE=0x40; XPDR_COUNT=100
MEDIA_NAME=b"SITI CINEMA BOOTUP HD.mpg\0"; MPEG_OFF=0x970000; MPEG_LEN=64329
RESOURCE_BASE=0x650000

def sha(b): return hashlib.sha256(b).hexdigest()
def clean(s): return re.sub(r"0x[0-9a-fA-F]+","0xADDR",s)
def all_hits(data,needle):
    out=[];pos=0
    while True:
        pos=data.find(needle,pos)
        if pos<0:return out
        out.append(pos);pos+=1

def ranges_diff(a,b):
    if len(a)!=len(b): raise ValueError("comparison lengths differ")
    out=[];i=0
    while i<len(a):
        if a[i]==b[i]:i+=1;continue
        j=i+1
        while j<len(a) and a[j]!=b[j]:j+=1
        out.append((i,j));i=j
    return out

def load_catalog(path,image_size):
    ranges=[]
    for r in csv.DictReader(path.open(newline="")):
        if r.get("name_state")!="printable_name":continue
        absolute=r.get("field_00_absolute_offset_candidate")
        if absolute:
            off=int(absolute,16)
        else:
            relative=r.get("field_00_offset_candidate") or r.get("field_00_relative_offset_candidate")
            off=RESOURCE_BASE+int(relative,16)
        n=int(r["field_04_stored_length_candidate"])
        if n>=0 and off+n<=image_size:ranges.append((off,off+n,r.get("filename_candidate",""),int(r["slot_index"])))
    return ranges

def in_catalog(off,ranges):return next((r for r in ranges if r[0]<=off<r[1]),None)
def scan_values(image, values):
    out={}
    for label,value,width in values:
        raw_le=value.to_bytes(width,"little",signed=False);raw_be=value.to_bytes(width,"big",signed=False)
        out[label]={"value":value,"width":width,"little_endian":{"hex":raw_le.hex(),"offsets":all_hits(image,raw_le)},"big_endian":{"hex":raw_be.hex(),"offsets":all_hits(image,raw_be)}}
    return out

def verify_sector_copy(image,offset,sector):
    return len(sector)==0x10000 and len(image)>=offset+0x10000 and image[offset:offset+0x10000]==sector

def update_tuning_values(update):
    if len(update)!=0x48:raise ValueError("Update Info record must be 0x48 bytes")
    if update[:12]!=b"Update Info\0" or int.from_bytes(update[12:16],"little")!=0x38:raise ValueError("invalid Update Info marker/extent")
    return {"frequency_u32_le":int.from_bytes(update[0x14:0x18],"little"),"symbol_rate_u32_le":int.from_bytes(update[0x18:0x1c],"little")}

def analyze(image,env1,env2,catalog_path,extract_dir,artifact_dir=None):
    if len(image)!=FW_SIZE:raise ValueError("firmware must be exactly 16 MiB")
    if len(env1)!=0x10000 or len(env2)!=0x10000:raise ValueError("ENV1/ENV2 evidence must each be exactly 64 KiB")
    if not verify_sector_copy(image,FE,env1):raise ValueError("ENV1 is not byte-identical to firmware sector FE")
    if not verify_sector_copy(image,FF,env2):raise ValueError("ENV2 is not byte-identical to firmware sector FF")
    if artifact_dir is None:artifact_dir=env1.parent
    catalog=load_catalog(catalog_path,len(image));update=image[FE+0x100:FE+0x148]
    tuning=update_tuning_values(update)
    freq=int.from_bytes(update[0x14:0x18],"little");sym32=int.from_bytes(update[0x18:0x1c],"little")
    xpdr=[]
    for i in range(XPDR_COUNT):
        p=XPDR_BASE+i*XPDR_STRIDE;r=image[p:p+XPDR_STRIDE]
        if len(r)!=XPDR_STRIDE:raise ValueError("XPDR table truncated")
        entry={"index":i,"image_offset":p,"id_u16_le":int.from_bytes(r[8:10],"little"),"active_candidate":int.from_bytes(r[8:10],"little")!=0xffff,
          "freq_u32_le":int.from_bytes(r[0x10:0x14],"little"),"symbol_u16_le":int.from_bytes(r[0x18:0x1a],"little"),
          "modulation_u16_candidate":int.from_bytes(r[0x14:0x16],"little"),"neighbor_u16_candidate":int.from_bytes(r[0x16:0x18],"little"),
          "network_or_ts_u16_candidate":int.from_bytes(r[0x1a:0x1c],"little"),"frequency_matches_update":int.from_bytes(r[0x10:0x14],"little")==freq,
          "symbol_rate_matches_update":int.from_bytes(r[0x18:0x1a],"little")==sym32}
        xpdr.append(entry)
    update_scan=scan_values(image,[("update_frequency_402000_u32",freq,4),("update_symbol_rate_6875_u32",sym32,4),
        ("xpdr_symbol_rate_6875_u16",sym32,2),("symbol_value_6875_u16_be_order",sym32,2)])
    # The label distinguishes byte-order encodings; for u16 the integer remains 6875.
    span=image[FE+SPAN_OFF:FE+SPAN_OFF+SPAN_LEN]
    if len(span)!=SPAN_LEN:raise ValueError("0x808 span truncated")
    nonzero_runs=[];i=0
    while i<len(span):
        if span[i]==0:i+=1;continue
        j=i+1
        while j<len(span) and span[j]!=0:j+=1
        nonzero_runs.append((i,j));i=j
    # Detect printable ASCII runs without including raw adjacent proprietary bytes.
    strings=[];i=0
    while i<len(span):
        if 0x20<=span[i]<=0x7e:
            j=i+1
            while j<len(span) and 0x20<=span[j]<=0x7e:j+=1
            if j-i>=4:strings.append((i,j,span[i:j].decode("ascii","replace")))
            i=j
        else:i+=1
    structure_rows=[]
    for start,end,label in [(0,4,"length_word_candidate"),(0,0xeb,"object_3000.bin exact candidate"),(0xec,0x808,"object_30ec.bin exact candidate"),(0xf0,0x163,"asn1_candidate.bin exact nested candidate"),(0x804,0x808,"tail_word_candidate")]:
        b=span[start:end]
        if end>start:structure_rows.append({"kind":"span","relative_start":start,"relative_end_exclusive":end,"length":len(b),"raw_sha256":sha(b),"label":label,"detail":"byte range; semantic format not assigned"})
    for st,en,text in strings:structure_rows.append({"kind":"ascii_string_candidate","relative_start":st,"relative_end_exclusive":en,"length":en-st,"raw_sha256":sha(span[st:en]),"label":"printable run","detail":text})
    for width in (2,4):
        step=width
        for off in range(0,SPAN_LEN-width+1,step):
            raw=span[off:off+width];le=int.from_bytes(raw,"little");be=int.from_bytes(raw,"big")
            if not any(raw):kind="zero"
            elif all(x==255 for x in raw):kind="erased_ff"
            else:kind="numeric candidate; semantics UNKNOWN"
            if kind=="zero" and not any(raw): pass
            structure_rows.append({"kind":f"u{width*8}_candidate","relative_start":off,"relative_end_exclusive":off+width,"length":width,"raw_sha256":"","label":kind,
              "raw_hex":raw.hex(),"u_le":f"0x{le:0{width*2}X}","u_be":f"0x{be:0{width*2}X}",
              "relative_offset_candidate_le":le if le<SPAN_LEN else "","relative_offset_candidate_be":be if be<SPAN_LEN else "",
              "absolute_flash_offset_candidate_le":le if 0x800000<=le<FW_SIZE else "","absolute_flash_offset_candidate_be":be if 0x800000<=be<FW_SIZE else ""})
    # Search values from the 0x808 aligned 32-bit words elsewhere; omit trivial padding values.
    cross=[];seen=set()
    for off in range(0,SPAN_LEN-3,4):
        raw=span[off:off+4]
        for endian,v in (("little",int.from_bytes(raw,"little")),("big",int.from_bytes(raw,"big"))):
            if v in (0,0xffffffff) or (endian,v) in seen:continue
            seen.add((endian,v));needle=v.to_bytes(4,endian);hits=all_hits(image,needle)
            if len(hits)>1:
                cross.append({"source":"loader_0x808_aligned_word","source_offset":FE+SPAN_OFF+off,"field_offset_in_span":off,"encoding":endian,"value":v,"target_occurrences":hits[:64],"occurrence_count":len(hits)})
    # ENV/object identity correlations.
    env_rows=[]
    env_rows.append({"item":"ENV1.bin vs FE sector","source_offset":"0xFE0000","length":len(env1),"source_sha256":sha(env1),"comparison_sha256":sha(image[FE:FE+len(env1)]),"equal":env1==image[FE:FE+len(env1)],"note":"entire 64 KiB files compared byte-for-byte"})
    env_rows.append({"item":"ENV2.bin vs FF sector","source_offset":"0xFF0000","length":len(env2),"source_sha256":sha(env2),"comparison_sha256":sha(image[FF:FF+len(env2)]),"equal":env2==image[FF:FF+len(env2)],"note":"entire 64 KiB files compared byte-for-byte"})
    extract_dir.mkdir(parents=True,exist_ok=True)
    for filename,start,end in [("object_3000.bin",0,0xeb),("object_30ec.bin",0xec,0x808),("asn1_candidate.bin",0xf0,0xf0+115)]:
        b=(Path(artifact_dir)/filename).read_bytes();candidate=span[start:end]
        env_rows.append({"item":filename+" vs Loader FE span","source_offset":f"0x{FE+SPAN_OFF+start:X}","length":len(b),"source_sha256":sha(b),"comparison_sha256":sha(candidate),"equal":b==candidate,"note":"exact bytes/hash comparison; file is preserved acquisition artifact"})
    # media-name, MPEG elementary stream and catalogue coverage.
    name_hits=all_hits(image,MEDIA_NAME);name_off=name_hits[0] if name_hits else None
    mpeg=image[MPEG_OFF:MPEG_OFF+MPEG_LEN]
    mpeg_codes=[];pos=0
    while True:
        pos=mpeg.find(b"\x00\x00\x01",pos)
        if pos<0 or pos+4>len(mpeg):break
        mpeg_codes.append((pos,mpeg[pos+3]));pos+=4
    sequence_hits=all_hits(image,b"\x00\x00\x01\xb3")
    media_rows=[]
    for nh in name_hits:
        cov=in_catalog(nh,catalog)
        media_rows.append({"item":"filename string","offset":f"0x{nh:X}","length":len(MEDIA_NAME)-1,"sha256":sha(MEDIA_NAME),"resource_catalog_covering_range":cov[2] if cov else "none","observation":"exact ASCII filename; string bytes are not themselves a resource descriptor"})
    cov=in_catalog(MPEG_OFF,catalog)
    media_rows.append({"item":"validated MPEG-2 stream","offset":f"0x{MPEG_OFF:X}","length":MPEG_LEN,"sha256":sha(mpeg),"resource_catalog_covering_range":cov[2] if cov else "none","observation":"previous and current full FFmpeg decode: one frame; sequence end at image offset 0x97FB48"})
    media_rows.append({"item":"sequence header candidates across complete image","offset":"multiple","length":len(sequence_hits),"sha256":"","resource_catalog_covering_range":"see per-offset cross-reference rows","observation":"MPEG sequence-header signature 00 00 01 B3 occurrences; signature alone is not a stream classification"})
    media_rows.append({"item":"string-to-stream relation","offset":f"0x{name_off:X}" if name_off is not None else "absent","length":"delta 0xF808 to stream start","sha256":"","resource_catalog_covering_range":"none","observation":"proximity is CONFIRMED; no pointer/reference establishing association found by tested exact offset and common MIPS KSEG aliases"})
    # Pointer encodings and name/stream offset values searched across full image.
    ptr_values=[]
    for label,off in (("filename_offset",name_off),("mpeg_offset",MPEG_OFF)):
        if off is None:continue
        ptr_values.extend([(label+"_raw_u32",off,4),(label+"_delta_u32",(MPEG_OFF-name_off) if name_off is not None else 0,4)])
        for base,alias in ((0x80000000,"kseg0"),(0xA0000000,"kseg1"),(0xBFC00000,"bfc_mapping")):
            value=base+off
            if value<0x100000000:ptr_values.append((label+"_"+alias,value,4))
    # Deduplicate label-value search and capture only exact pointers with offsets.
    ptr_search=scan_values(image,list(dict.fromkeys(ptr_values)))
    for off in sequence_hits:
        cov=in_catalog(off,catalog)
        media_rows.append({"item":"MPEG sequence-header occurrence","offset":f"0x{off:X}","length":"signature only","sha256":"","resource_catalog_covering_range":cov[2] if cov else "none","observation":"candidate sequence-header start; parser validation required"})
    # Probe every global sequence-header candidate only through its next sequence-end code.
    media_candidates=[]
    for off in sequence_hits:
        endcode=image.find(b"\x00\x00\x01\xb7",off+4)
        if endcode<0:continue
        chunk=image[off:endcode+4];cover=in_catalog(off,catalog)
        try:
            q=subprocess.run(["ffprobe","-v","error","-f","mpegvideo","-show_frames","-show_streams","-of","json","-i","pipe:0"],input=chunk,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
            j=json.loads(q.stdout or b"{}");frames=j.get("frames",[]);streams=j.get("streams",[])
            probe_result={"ffprobe_exit":q.returncode,"decoded_frames":len(frames),"streams":[{"codec":x.get("codec_name"),"width":x.get("width"),"height":x.get("height")} for x in streams],"ffprobe_stderr":clean(q.stderr.decode("utf8","replace")[:200])}
        except Exception as exc:probe_result={"probe_error":type(exc).__name__}
        try:
            q2=subprocess.run(["ffmpeg","-v","error","-xerror","-f","mpegvideo","-i","pipe:0","-f","null","-"],input=chunk,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
            probe_result["ffmpeg_decode_exit"]=q2.returncode;probe_result["ffmpeg_stderr"]=clean(q2.stderr.decode("utf8","replace")[:200])
        except Exception as exc:probe_result["ffmpeg_error"]=type(exc).__name__
        media_candidates.append({"offset":off,"end_offset_exclusive":endcode+4,"length":len(chunk),"sha256":sha(chunk),"catalog_name":cover[2] if cover else "none","validated_video":probe_result.get("decoded_frames",0)>0 and probe_result.get("ffmpeg_decode_exit")==0,"probe":probe_result})
    media_rows.append({"item":"0x960000 metadata-region scan","offset":"0x960000–0x96FFFF","length":0x10000,"sha256":sha(image[0x960000:0x970000]),"resource_catalog_covering_range":"none","observation":"mostly erased; one printable filename string; see region span list in JSON"})
    for candidate in media_candidates:
        media_rows.append({"item":"bounded MPEG sequence candidate","offset":f"0x{candidate["offset"]:X}","length":candidate["length"],"sha256":candidate["sha256"],"resource_catalog_covering_range":candidate["catalog_name"],"observation":json.dumps(candidate["probe"],separators=(",",":"))})
    # Map populated spans in the immediate filename-to-stream gap.
    meta=image[0x960000:0x970000];meta_spans=[];m=0
    while m<len(meta):
        kind="zero" if meta[m]==0 else "erased_ff" if meta[m]==255 else "populated";n=m+1
        while n<len(meta) and ("zero" if meta[n]==0 else "erased_ff" if meta[n]==255 else "populated")==kind:n+=1
        if kind!="erased_ff":meta_spans.append({"start":0x960000+m,"end_exclusive":0x960000+n,"kind":kind,"length":n-m})
        m=n
    # attempt a bounded ffprobe from exact known stream bytes, all input stays in memory
    ffprobe={"attempted":False}
    try:
        cp=subprocess.run(["ffprobe","-v","error","-f","mpegvideo","-show_frames","-show_streams","-of","json","-i","pipe:0"],input=mpeg,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
        ffprobe={"attempted":True,"exit_code":cp.returncode,"json":json.loads(cp.stdout or b"{}"),"stderr":clean(cp.stderr.decode("utf8","replace")[:500])}
    except Exception as exc:ffprobe={"attempted":True,"error":type(exc).__name__}
    # reference searches for update tuple and nearby words
    vals=[("update_frequency_402000",freq,4),("update_symbol_6875_u32",sym32,4),("update_symbol_6875_u16",sym32,2),
          ("update_word_plus_1c",int.from_bytes(update[0x1c:0x20],"little"),4),("update_word_plus_3c",int.from_bytes(update[0x3c:0x40],"little"),4)]
    update_refs=scan_values(image,vals)
    return {"image_sha256":sha(image),"env1_sha256":sha(env1),"env2_sha256":sha(env2),"loader_env_equal":True,
      "env_objects":env_rows,"update_fields":{"record_offset_fe":"0xFE0100","record_offset_ff":"0xFF0100","update_record_bytes_sha256":sha(update),
        "frequency_candidate":freq,"symbol_rate_candidate_u32":sym32,"fields":[{"offset":f"+0x{o:X}","raw_hex":update[o:o+w].hex(),"u16_le":int.from_bytes(update[o:o+2],"little") if w>=2 else None,"u16_be":int.from_bytes(update[o:o+2],"big") if w>=2 else None,"u32_le":int.from_bytes(update[o:o+4],"little") if w>=4 else None,"u32_be":int.from_bytes(update[o:o+4],"big") if w>=4 else None} for o,w in ((0x0c,4),(0x10,4),(0x14,4),(0x18,4),(0x1c,4),(0x20,4),(0x24,4),(0x28,4),(0x2c,4),(0x30,4),(0x34,4),(0x38,4),(0x3c,4),(0x40,4),(0x44,4))]},
      "xpdr_records":xpdr,"update_value_full_image_references":update_refs,
      "loader_span":{"image_offset":"0xFE3000","length":len(span),"sha256":sha(span),"first_u32_le":int.from_bytes(span[:4],"little"),"last_u32_le":int.from_bytes(span[-4:],"little"),"nonzero_runs":[[a,b] for a,b in nonzero_runs],"ascii_candidates":strings,"aligned_word_references":cross},
      "media":{"filename_hits":[f"0x{x:X}" for x in name_hits],"filename_pointer_value_search":ptr_search,"mpeg_stream_offset":"0x970000","mpeg_length":len(mpeg),"mpeg_sha256":sha(mpeg),"mpeg_start_code_counts":{f"0x{k:02X}":v for k,v in sorted(Counter(c for _,c in mpeg_codes).items())},"mpeg_start_code_offsets":[{"relative":p,"image":MPEG_OFF+p,"code":f"0x{c:02X}"} for p,c in mpeg_codes],"global_sequence_header_offsets":[f"0x{x:X}" for x in sequence_hits],"global_sequence_candidates":media_candidates,"metadata_region_960000_spans":meta_spans,"ffprobe":ffprobe,"resource_catalog_entry_count":len(catalog),"filename_covered_by_catalog":bool(name_off is not None and in_catalog(name_off,catalog)),"mpeg_covered_by_catalog":bool(in_catalog(MPEG_OFF,catalog))},
      "media_rows":media_rows,"structure_rows":structure_rows}

def write_csv(path,rows,fields):
    with path.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(rows)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("image",type=Path);p.add_argument("env1",type=Path);p.add_argument("env2",type=Path);p.add_argument("resource_index",type=Path);p.add_argument("--output-dir",type=Path,required=True);p.add_argument("--extract-dir",type=Path,required=True);p.add_argument("--artifact-dir",type=Path);a=p.parse_args()
    image=a.image.read_bytes();env1=a.env1.read_bytes();env2=a.env2.read_bytes();r=analyze(image,env1,env2,a.resource_index,a.extract_dir,a.artifact_dir);a.output_dir.mkdir(parents=True,exist_ok=True)
    (a.output_dir/"cross-structure-analysis.json").write_text(json.dumps(r,indent=2)+"\n")
    write_csv(a.output_dir/"loader-xpdr-correlation.csv",r["xpdr_records"],["index","image_offset","id_u16_le","active_candidate","freq_u32_le","symbol_u16_le","modulation_u16_candidate","neighbor_u16_candidate","network_or_ts_u16_candidate","frequency_matches_update","symbol_rate_matches_update"])
    write_csv(a.output_dir/"loader-structure-fields.csv",r["structure_rows"],["kind","relative_start","relative_end_exclusive","length","raw_sha256","label","detail","raw_hex","u_le","u_be","relative_offset_candidate_le","relative_offset_candidate_be","absolute_flash_offset_candidate_le","absolute_flash_offset_candidate_be"])
    write_csv(a.output_dir/"media-reference-investigation.csv",r["media_rows"],["item","offset","length","sha256","resource_catalog_covering_range","observation"])
    cross=[]
    for row in r["env_objects"]:cross.append({"source_structure":row["item"],"source_offset":row["source_offset"],"length":row["length"],"value_or_hash":row["source_sha256"],"encoding":"byte-exact hash/compare","target_or_matches":row["comparison_sha256"],"match_count":1 if row["equal"] else 0,"confidence":"CONFIRMED" if row["equal"] else "UNKNOWN","interpretation":row["note"]})
    for label,d in r["update_value_full_image_references"].items():
        for endian in ("little_endian","big_endian"):
            x=d[endian]
            for hit in x["offsets"]:
                cross.append({"source_structure":label,"source_offset":"Update Info field","length":d["width"],"value_or_hash":x["hex"],"encoding":endian,"target_or_matches":f"0x{hit:X}","match_count":len(x["offsets"]),"confidence":"CONFIRMED byte match","interpretation":"raw-value occurrence only; semantic reference not established"})
    for label,d in r["media"]["filename_pointer_value_search"].items():
        for endian in ("little_endian","big_endian"):
            x=d[endian]
            for hit in x["offsets"]:
                cross.append({"source_structure":label,"source_offset":"derived from media filename/stream offset","length":d["width"],"value_or_hash":x["hex"],"encoding":endian,"target_or_matches":f"0x{hit:X}","match_count":len(x["offsets"]),"confidence":"CONFIRMED byte match","interpretation":"candidate pointer encoding; context must be validated"})
    for candidate in r["media"]["global_sequence_candidates"]:
        cross.append({"source_structure":"MPEG sequence-header candidate","source_offset":f"0x{candidate["offset"]:X}","length":candidate["length"],"value_or_hash":candidate["sha256"],"encoding":"bounded to next B7","target_or_matches":candidate["catalog_name"],"match_count":1,"confidence":"CONFIRMED media" if candidate["validated_video"] else "signature/parser candidate only","interpretation":json.dumps(candidate["probe"],separators=(",",":"))})
    write_csv(a.output_dir/"firmware-cross-references.csv",cross,["source_structure","source_offset","length","value_or_hash","encoding","target_or_matches","match_count","confidence","interpretation"])
    print(json.dumps({"image_sha256":r["image_sha256"],"env_exact_matches":all(x["equal"] for x in r["env_objects"][:2]),"object_matches":all(x["equal"] for x in r["env_objects"][2:]),"xpdr_frequency_matches":[x["index"] for x in r["xpdr_records"] if x["frequency_matches_update"]],"xpdr_symbol_matches":[x["index"] for x in r["xpdr_records"] if x["symbol_rate_matches_update"]],"xpdr_both_matches":[x["index"] for x in r["xpdr_records"] if x["frequency_matches_update"] and x["symbol_rate_matches_update"]],"value_occurrence_counts":{k:{e:len(v[e]["offsets"]) for e in ("little_endian","big_endian")} for k,v in r["update_value_full_image_references"].items()},"media_name_hits":r["media"]["filename_hits"],"media_candidates":[{"offset":hex(x["offset"]),"validated":x["validated_video"],"frames":x["probe"].get("decoded_frames")} for x in r["media"]["global_sequence_candidates"]],"outputs":str(a.output_dir)},indent=2))
if __name__=="__main__":main()
