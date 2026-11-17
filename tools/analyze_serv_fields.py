#!/usr/bin/env python3
"""Export raw candidate service fields and compare a candidate field to XPDR row indices."""
from __future__ import annotations
import argparse, csv, hashlib, json, struct
from collections import Counter, defaultdict
from pathlib import Path

SERV_START=0x801930; SERV_COUNT=1300; SERV_STRIDE=300
XPDR_START=0x800018; XPDR_COUNT=100; XPDR_STRIDE=64
FIELD_OFFSETS=(0x2c,0x2e,0x30,0x32,0x34,0x36)

def analyze(data:bytes, serv_start:int=SERV_START, serv_count:int=SERV_COUNT,
            serv_stride:int=SERV_STRIDE, xpdr_start:int=XPDR_START,
            xpdr_count:int=XPDR_COUNT, xpdr_stride:int=XPDR_STRIDE):
    if min(serv_start,serv_count,serv_stride,xpdr_start,xpdr_count,xpdr_stride)<0 or serv_stride==0 or xpdr_stride==0:
        raise ValueError("invalid range")
    if serv_start+serv_count*serv_stride>len(data) or xpdr_start+xpdr_count*xpdr_stride>len(data):
        raise ValueError("table exceeds input")
    rows=[]; counts={o:Counter() for o in FIELD_OFFSETS}; groups=defaultdict(list)
    both_ffff=0; same_status=0; named=0
    for i in range(serv_count):
        off=serv_start+i*serv_stride; r=data[off:off+serv_stride]
        name=r[:0x20].split(b"\0",1)[0].decode("ascii","replace")
        vals={o:struct.unpack_from("<H",r,o)[0] for o in FIELD_OFFSETS}
        for o,v in vals.items(): counts[o][v]+=1
        both_ffff += vals[0x2c]==vals[0x2e]==0xffff
        same_status += (vals[0x2c]==0xffff)==(vals[0x2e]==0xffff)
        named += bool(name)
        if vals[0x2e] != 0xffff: groups[vals[0x2e]].append(i)
        rows.append({"index":i,"image_offset":off,"name_candidate":name,
          **{f"u16_{o:02x}_candidate":vals[o] for o in FIELD_OFFSETS},
          "bytes_2c_37_hex":r[0x2c:0x38].hex(),"bytes_38_3b_hex":r[0x38:0x3c].hex(),
          "record_sha256":hashlib.sha256(r).hexdigest()})
    xpdr=[]
    for i in range(xpdr_count):
        r=data[xpdr_start+i*xpdr_stride:xpdr_start+(i+1)*xpdr_stride]
        idx=struct.unpack_from("<H",r,8)[0]
        if idx!=0xffff:
            xpdr.append({"row_index":i,"id_candidate":idx,"u32_10_candidate":struct.unpack_from("<I",r,0x10)[0],
              "u16_18_candidate":struct.unpack_from("<H",r,0x18)[0],"u16_1a_candidate":struct.unpack_from("<H",r,0x1a)[0]})
    xmap={x["row_index"]:x for x in xpdr}; cross=[]
    for val,ixs in sorted(groups.items()):
        contiguous=all(b==a+1 for a,b in zip(ixs,ixs[1:]))
        xp=xmap.get(val)
        cross.append({"field_0x2e_value":val,"service_record_count":len(ixs),"first_record_index":ixs[0],
          "last_record_index":ixs[-1],"single_contiguous_run":contiguous,"transponder_row_exists":xp is not None,
          "xpdr_id_candidate":xp["id_candidate"] if xp else "","xpdr_u32_10_candidate":xp["u32_10_candidate"] if xp else "",
          "xpdr_u16_18_candidate":xp["u16_18_candidate"] if xp else "","service_indices_json":json.dumps(ixs),
          "service_records_json":json.dumps([{"index":i,"service_id_candidate":rows[i]["u16_2c_candidate"],"name_candidate":rows[i]["name_candidate"]} for i in ixs],ensure_ascii=False)})
    summary={"service_record_count":serv_count,"named_record_candidates":named,
      "u16_candidate_distributions":{f"0x{o:02X}":{"distinct":len(c),"counts":{f"0x{v:04X}":n for v,n in sorted(c.items())}} for o,c in counts.items()},
      "offset_0x2c_0x2e_joint":{"both_ffff":both_ffff,"same_ffff_status":same_status,"both_not_ffff":same_status-both_ffff},
      "offset_0x2e_to_xpdr_row_index":{"candidate_reference_row_count":sum(len(ixs) for v,ixs in groups.items() if v in xmap),
        "candidate_reference_values":sorted(v for v in groups if v in xmap),
        "all_candidate_reference_values_have_active_xpdr_row":all(v in xmap for v in groups if v < xpdr_count),
        "unmatched_non_ffff_values":{str(v):len(ixs) for v,ixs in groups.items() if v not in xmap},
        "unreferenced_active_xpdr_rows":sorted(set(xmap)-set(groups)),
        "candidate_reference_rows_with_non_ffff_0x2c":sum(1 for row in rows if row["u16_2e_candidate"] in xmap and row["u16_2c_candidate"]!=0xffff),
        "candidate_reference_groups":sum(v in xmap for v in groups),"all_groups_single_contiguous_run":all(x["single_contiguous_run"] for x in cross if x["transponder_row_exists"])},
      "interpretation":"Raw u16 candidates; matching field 0x2E to XPDR array index is an inferred cross-table relationship, not a proven proprietary semantic."}
    return summary,rows,cross

def write(summary,rows,cross,out:Path):
    out.mkdir(parents=True,exist_ok=True);(out/"serv-field-summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    for name,data in (("serv-field-candidates.csv",rows),("serv-xpdr-crossref.csv",cross)):
        with (out/name).open("w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=list(data[0]) if data else []);w.writeheader();w.writerows(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("image",type=Path);p.add_argument("--output",type=Path,required=True);p.add_argument("--serv-start",type=lambda x:int(x,0),default=SERV_START);p.add_argument("--xpdr-start",type=lambda x:int(x,0),default=XPDR_START);a=p.parse_args()
    s,r,x=analyze(a.image.read_bytes(),serv_start=a.serv_start,xpdr_start=a.xpdr_start);write(s,r,x,a.output)
    print(json.dumps({"service_record_count":s["service_record_count"],"crossref":s["offset_0x2e_to_xpdr_row_index"],"output":str(a.output)},indent=2))
if __name__=="__main__":main()
