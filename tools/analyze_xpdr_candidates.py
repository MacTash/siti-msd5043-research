#!/usr/bin/env python3
"""Analyze measured xpdr fields and cross-check candidate IDs against serv records."""
import argparse, collections, csv, hashlib, json, struct
from pathlib import Path
from parse_xpdr import parse_image


def unpack(raw, off, size=2):
    return int.from_bytes(raw[off:off+size], "little")


def analyze_entries(raw_entries):
    active = [i for i,r in enumerate(raw_entries) if unpack(r, 8) != 0xffff]
    rows=[]
    for i,raw in enumerate(raw_entries):
        rows.append({
            "index":i,"raw_hex":raw.hex(),"active_candidate":i in active,
            "u16_00_candidate":unpack(raw,0),"u16_02_candidate":unpack(raw,2),
            "u16_04_candidate":unpack(raw,4),"u16_06_candidate":unpack(raw,6),
            "u16_08_candidate":unpack(raw,8),"u16_0a_candidate":unpack(raw,10),
            "u16_0c_candidate":unpack(raw,12),"u16_0e_candidate":unpack(raw,14),
            "u32_10_candidate":unpack(raw,16,4),"u16_14_candidate":unpack(raw,20),
            "u16_16_candidate":unpack(raw,22),"u16_18_candidate":unpack(raw,24),
            "u16_1a_candidate":unpack(raw,26),"bytes_1c_2f_hex":raw[28:48].hex(),
            "bytes_30_3b_hex":raw[48:60].hex(),"bytes_3c_3f_hex":raw[60:64].hex(),
        })
    links = bool(active) and all(
        unpack(raw_entries[i],0)==(0xffff if n==0 else active[n-1]) and
        unpack(raw_entries[i],2)==(0xffff if n==len(active)-1 else active[n+1])
        for n,i in enumerate(active))
    tail_templates=collections.Counter(raw_entries[i] for i in range(len(raw_entries)) if i not in active)
    summary={
        "entry_count":len(raw_entries),"active_candidate_count":len(active),
        "active_candidate_indices":active,"prev_next_chain_pattern":links,
        "unused_template_count":len(raw_entries)-len(active),
        "unique_unused_templates":len(tail_templates),
        "unused_template_sha256":hashlib.sha256(tail_templates.most_common(1)[0][0]).hexdigest() if tail_templates else "",
        "field_distributions":{
          name:dict((str(k),v) for k,v in collections.Counter(r[key] for r in rows if r["active_candidate"]).most_common())
          for name,key in [("u16_00","u16_00_candidate"),("u16_02","u16_02_candidate"),("u16_04","u16_04_candidate"),("u16_06","u16_06_candidate"),("u16_08","u16_08_candidate"),("u16_0a","u16_0a_candidate"),("u16_14","u16_14_candidate"),("u16_16","u16_16_candidate"),("u16_18","u16_18_candidate"),("u16_1a","u16_1a_candidate")]
        },
        "frequency_u32_10_range":[min(r["u32_10_candidate"] for r in rows if r["active_candidate"]),max(r["u32_10_candidate"] for r in rows if r["active_candidate"])],
        "frequency_u32_10_mod_8000":sorted({r["u32_10_candidate"]%8000 for r in rows if r["active_candidate"]}),
    }
    return summary,rows


def channel_crossref(image: bytes, ids: set[int], frequencies: set[int], symbol_rates: set[int]):
    base=0x801930;count=1300;stride=300
    id_hits=collections.defaultdict(list);freq_hits=collections.defaultdict(list);rate_hits=collections.defaultdict(list)
    for i in range(count):
        r=image[base+i*stride:base+(i+1)*stride]
        for off in range(0,stride-1,2):
            v=unpack(r,off)
            if v in ids:id_hits[off].append((i,v))
            if v in symbol_rates:rate_hits[off].append((i,v))
        for off in range(0,stride-3,4):
            v=unpack(r,off,4)
            if v in frequencies:freq_hits[off].append((i,v))
    output=[]
    for label,mapping in (("xpdr_field_08_candidate_ids",id_hits),("xpdr_field_10_frequency_candidates",freq_hits),("xpdr_field_18_symbol_rate_candidates",rate_hits)):
        for off,hits in sorted(mapping.items()):
            output.append({"match_set":label,"service_record_offset":f"+0x{off:X}","match_count":len(hits),"sample_record_value_pairs":json.dumps(hits[:20])})
    return output


def write_csv(path,rows):
    with path.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else []);w.writeheader();w.writerows(rows)


def main():
    p=argparse.ArgumentParser();p.add_argument("--image",type=Path,required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    image=a.image.read_bytes();parsed=parse_image(image);raw=[bytes.fromhex(e["raw_hex"]) for e in parsed["regions"]["A"]["entries"]]
    summary,rows=analyze_entries(raw);summary["regions_ab_entries_identical"]=parsed["comparison"]["identical_entries"]==100
    ids={r["u16_08_candidate"] for r in rows if r["active_candidate"]}
    freqs={r["u32_10_candidate"] for r in rows if r["active_candidate"]}
    rates={r["u16_18_candidate"] for r in rows if r["active_candidate"]}
    cross=channel_crossref(image,ids,freqs,rates)
    a.out.mkdir(parents=True,exist_ok=True);write_csv(a.out/"xpdr-field-analysis.csv",rows);write_csv(a.out/"xpdr-service-crossref.csv",cross)
    (a.out/"xpdr-field-summary.json").write_text(json.dumps(summary,indent=2)+"\n");print(json.dumps(summary,indent=2));print('crossref_rows',len(cross))

if __name__=="__main__":main()
