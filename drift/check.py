import json
import subprocess
import sys

live = json.loads(subprocess.check_output(["kubectl","-n","app-test","get","deploy","demo-app","-o","json"]))
spec = live["spec"]["template"]["spec"]["containers"][0]
issues = []
if spec.get("securityContext",{}).get("allowPrivilegeEscalation", True):
    issues.append("allowPrivilegeEscalation true in live")
if not spec.get("securityContext",{}).get("readOnlyRootFilesystem", False):
    issues.append("readOnlyRootFilesystem false in live")
if "latest" in spec.get("image", ""):
    issues.append("Image tag 'latest' in live deployment")
print(json.dumps({"drift_issues": issues}, indent=2))
sys.exit(1 if issues else 0)
