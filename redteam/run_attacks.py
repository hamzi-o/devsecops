import argparse
import json
import time
import requests

def get(target, path, method="GET", json_body=None):
    url = target.rstrip("/") + path
    try:
        r = requests.request(method, url, timeout=10, json=json_body)
        return {
            "method": method,
            "path": path,
            "status": r.status_code,
            "len": len(r.text),
            "response_snippet": r.text[:200]
        }
    except Exception as e:
        return {"method": method, "path": path, "error": str(e)}

def run(target):
    res = []

    # Normal probes
    res.append(get(target, "/healthz"))
    res.append(get(target, "/greet/Hamza"))
    res.append(get(target, "/echo", method="POST", json_body={"data":{"k":"v"}}))
    for i in [1,2,999999]:
        res.append(get(target, f"/items/{i}"))
        time.sleep(0.2)
    res.append(get(target, "/admin"))
    res.append(get(target, "/nonexistent"))

    # Security headers
    hdr = requests.get(target, timeout=10).headers
    expected = [
        "Content-Security-Policy","X-Content-Type-Options","X-Frame-Options",
        "Referrer-Policy","Strict-Transport-Security","Permissions-Policy",
        "Cache-Control","Pragma","Expires"
    ]
    missing = [h for h in expected if h not in hdr]
    res.append({"headers_check_missing": missing})

    # Directory traversal / file leaks
    res.append(get(target, "/../../etc/passwd"))
    res.append(get(target, "/.git/config"))
    res.append(get(target, "/.env"))

    # SQLi check
    res.append(get(target, "/items/1' OR '1'='1"))

    # Command injection probe
    res.append(get(target, "/echo", method="POST", json_body={"data":{"test":";ls"}}))

    # Open redirect
    res.append(get(target, "/redirect?url=http://evil.com"))

    # HTTPS check
    if target.startswith("http://"):
        res.append({"https_check": "Target is using plain HTTP, not HTTPS!"})

    return res

if __name__=="__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", default="redteam_results.json")
    a = ap.parse_args()
    out = run(a.target)
    open(a.out,"w").write(json.dumps(out, indent=2))
    print("Red team done:", a.out)
