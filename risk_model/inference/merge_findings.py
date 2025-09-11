import json
import argparse
import os

def parse_sast(file):
    if not os.path.exists(file):
        return []
    with open(file) as f:
        data = json.load(f)
        return [
            {
                "type": "sast",
                "title": finding.get("check_name", "Unknown"),
                "location": finding.get("path", "N/A"),
                "severity": finding.get("severity", "LOW"),
                "description": finding.get("description", ""),
                "cwe": finding.get("cwe", []),
                "line": finding.get("line", 0)
            }
            for finding in data.get("results", [])
        ]

def parse_sca(file):
    if not os.path.exists(file):
        return []
    with open(file) as f:
        data = json.load(f)
        return [
            {
                "type": "sca",
                "title": finding.get("Vulnerability", {}).get("ID", "Unknown"),
                "location": f"pkg:{finding.get('PkgName', 'unknown')}:{finding.get('InstalledVersion', 'unknown')}",
                "severity": finding.get("Severity", "LOW"),
                "description": finding.get("Description", ""),
                "cve": finding.get("VulnerabilityID", "")
            }
            for finding in data.get("Results", [])
        ]

def parse_iac(file):
    if not os.path.exists(file):
        return []
    with open(file) as f:
        data = json.load(f)
        # Handle case where data is an empty list
        if isinstance(data, list):
            return []
        return [
            {
                "type": "iac",
                "title": finding.get("check_id", "Unknown"),
                "location": finding.get("file_path", "N/A"),
                "severity": finding.get("severity", "LOW"),
                "description": finding.get("check_name", ""),
                "line": finding.get("file_line_range", [0])[0]
            }
            for finding in data.get("results", [])
        ]

def parse_secrets(file):
    if not os.path.exists(file):
        return []
    with open(file) as f:
        data = json.load(f)
        return [
            {
                "type": "secrets",
                "title": finding.get("Title", "Unknown"),
                "location": finding.get("File", "N/A"),
                "severity": "HIGH",
                "description": finding.get("Description", ""),
                "line": finding.get("StartLine", 0)
            }
            for finding in data
        ]

def parse_dast(file):
    if not os.path.exists(file):
        return []
    with open(file) as f:
        data = json.load(f)
        return [
            {
                "type": "dast",
                "title": alert.get("name", "Unknown"),
                "location": alert.get("url", "N/A"),
                "severity": alert.get("risk", "LOW"),
                "description": alert.get("description", ""),
                "cwe": alert.get("cweid", "")
            }
            for alert in data.get("site", [{}])[0].get("alerts", [])
        ]

def main():
    parser = argparse.ArgumentParser(description="Merge security findings into JSONL")
    parser.add_argument("--sast", help="SAST findings (semgrep)")
    parser.add_argument("--sca", help="SCA findings (trivy)")
    parser.add_argument("--iac", help="IaC findings (checkov)")
    parser.add_argument("--secrets", help="Secrets findings (gitleaks)")
    parser.add_argument("--dast", help="DAST findings (OWASP ZAP)")
    parser.add_argument("--out", help="Output JSONL file", required=True)
    args = parser.parse_args()

    findings = []
    findings.extend(parse_sast(args.sast))
    findings.extend(parse_sca(args.sca))
    findings.extend(parse_iac(args.iac))
    findings.extend(parse_secrets(args.secrets))
    findings.extend(parse_dast(args.dast))

    with open(args.out, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    print(f"Merged {len(findings)} findings into {args.out}")

if __name__ == "__main__":
    main()
