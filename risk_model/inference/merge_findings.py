import json
import argparse
from pathlib import Path

def load_json(file_path):
    if Path(file_path).exists():
        with open(file_path, 'r') as f:
            return json.load(f)
    return []

def load_dast_json(file_path):
    findings = []
    if Path(file_path).exists():
        with open(file_path, 'r') as f:
            data = json.load(f)
            for alert in data.get('site', [{}])[0].get('alerts', []):
                findings.append({
                    'id': alert.get('alertRef', ''),
                    'type': 'vuln',
                    'location': alert.get('url', 'Unknown'),
                    'cvss_score': float(alert.get('riskdesc', '0.0').split('(')[0].strip() or 0.0),
                    'epss_score': 0.0,  # Placeholder
                    'is_kev': 0,  # Placeholder
                    'description': alert.get('desc', ''),
                    'source': 'zap'
                })
    return findings

def main():
    parser = argparse.ArgumentParser(description="Merge security findings")
    parser.add_argument('--sast', help="SAST findings (JSON)")
    parser.add_argument('--secrets', help="Secrets findings (JSON)")
    parser.add_argument('--iac', help="IaC findings (JSON)")
    parser.add_argument('--sca', help="SCA findings (JSON)")
    parser.add_argument('--dast', help="DAST findings (JSON)")
    parser.add_argument('--out', required=True, help="Output JSONL file")
    args = parser.parse_args()

    findings = []
    findings.extend(load_json(args.sast))
    findings.extend(load_json(args.secrets))
    findings.extend(load_json(args.iac))
    findings.extend(load_json(args.sca))
    findings.extend(load_dast_json(args.dast))

    with open(args.out, 'w') as f:
        for finding in findings:
            f.write(json.dumps(finding) + '\n')

if __name__ == "__main__":
    main()
