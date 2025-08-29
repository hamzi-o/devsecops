import yaml
import json
import sys

try:
    cfg = yaml.safe_load(open("adaptive/gate_config.yaml"))
except FileNotFoundError:
    print("gate_config.yaml not found")
    sys.exit(1)
thr = cfg["thresholds"]["base"]
tier = cfg["context"]["asset_tier"]
exposed = cfg["context"]["internet_exposed"]
kevd = cfg["context"]["recent_kev_delta_24h"]
thr += cfg["thresholds"]["adjustments"]["asset_tier"].get(tier, 0.0)
thr += -0.05 if exposed else 0.0
thr += -0.05 if kevd and kevd > 0 else 0.0
print(json.dumps({"adaptive_threshold": round(thr, 2)}))
