import argparse
import json
import os

def load_json(path, default):
    if not os.path.exists(path): return default
    try: return json.load(open(path))
    except: return default

def from_semgrep(d):
    out = []
    for r in d.get("results", []):
        out.append({
            "type": "SAST",
            "title": f"{r.get('check_id')} in {r.get('path')}",
            "text": r.get("extra",{}).get("message",""),
            "severity": r.get("extra",{}).get("severity","INFO"),
            "tool": "semgrep",
            "cve": r.get("extra",{}).get("cve",""),
            "location": r.get("path","unknown")
        })
    return out

def from_gitleaks(d):
    items = d if isinstance(d,list) else d.get("findings",[])
    out = []
    for r in items:
        out.append({
            "type": "SECRETS",
            "title": f"{r.get('RuleID')} in {r.get('File')}",
            "text": r.get("Description",""),
            "severity": "HIGH",
            "tool": "gitleaks",
            "location": r.get("File","unknown")
        })
    return out

def from_checkov(d):
    out = []
    for r in d.get("results",{}).get("failed_checks",[]):
        out.append({
            "type": "IAC",
            "title": f"{r.get('check_id')}: {r.get('check_name')}",
            "text": r.get("file_path",""),
            "severity": r.get("severity","MEDIUM"),
            "tool": "checkov",
            "location": r.get("file_path","unknown")
        })
    return out

def from_trivy(d):
    out = []
    for res in d.get("Results",[]):
        for v in (res.get("Vulnerabilities") or []):
            location = f"{res.get('Target','unknown')}:{v.get('PkgName','unknown')}"
            out.append({
                "type": "SCA",
                "title": f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                "text": v.get("Title") or v.get("Description",""),
                "severity": v.get("Severity","UNKNOWN"),
                "tool": "trivy",
                "cve": v.get("VulnerabilityID"),
                "location": location
            })
    return out

if __name__=="__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sast",default="sast.json")
    ap.add_argument("--sca",default="sca.json")
    ap.add_argument("--iac",default="iac.json")
    ap.add_argument("--secrets",default="secrets.json")
    ap.add_argument("--out",required=True)
    a = ap.parse_args()
    merged = []
    merged += from_semgrep(load_json(a.sast,{}))
    merged += from_gitleaks(load_json(a.secrets,[]))
    merged += from_checkov(load_json(a.iac,{}))
    merged += from_trivy(load_json(a.sca,{}))
    with open(a.out,"w") as f:
        for m in merged: f.write(json.dumps(m)+"\n")
    print(f"Merged {len(merged)} findings into {a.out}")
