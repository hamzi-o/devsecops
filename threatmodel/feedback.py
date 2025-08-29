import json
import yaml
import sys

try:
    tm = yaml.safe_load(open("threatmodel/threat_model.yaml"))
except FileNotFoundError:
    print("threat_model.yaml not found")
    sys.exit(1)
findings = [json.loads(l) for l in open("enriched.jsonl")] if len(sys.argv) > 1 else []
high = sum(1 for f in findings if f.get("priority") in ["P1","P2"] and f.get("type") in ["SCA","IAC"])
dast_focus = "active" if any(f.get("type")=="SCA" and f.get("priority")=="P1" for f in findings) else "baseline"
tm["services"][0]["focus"]["dast"] = dast_focus
open("threatmodel/threat_model.yaml","w").write(yaml.safe_dump(tm))
print(f"Updated threat model DAST focus: {dast_focus}")
