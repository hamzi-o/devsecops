import json, sys, os

threshold = float(os.environ.get("THRESH", "0"))
violations = 0

try:
    with open("enriched.jsonl", "r") as f:
        for line in f:
            if line.strip():
                finding = json.loads(line)
                risk_score = finding.get("risk_score", 0)
                if risk_score >= threshold:
                    violations += 1
                    print(f"High-risk finding: {finding.get('title','Unknown')} (score: {risk_score})", file=sys.stderr)
except FileNotFoundError:
    print("No enriched findings file found", file=sys.stderr)
except Exception as e:
    print(f"Error processing findings: {e}", file=sys.stderr)

print(violations)
