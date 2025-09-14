import json
import argparse
import os

def parse_sast(file):
    if not os.path.exists(file):
        return []
    try:
        with open(file) as f:
            data = json.load(f)
            if isinstance(data, list):
                return []
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
                if isinstance(finding, dict)
            ]
    except (json.JSONDecodeError, Exception) as e:
        print(f"Error parsing SAST file {file}: {e}")
        return []

def parse_sca(file):
    if not os.path.exists(file):
        return []
    try:
        with open(file) as f:
            data = json.load(f)
            # Handle case where data is an empty list
            if isinstance(data, list):
                return []
            results = []
            for result in data.get("Results", []):
                if not isinstance(result, dict):
                    continue
                for vulnerability in result.get("Vulnerabilities", []):
                    if isinstance(vulnerability, dict):
                        results.append({
                            "type": "sca",
                            "title": vulnerability.get("VulnerabilityID", "Unknown"),
                            "location": f"pkg:{vulnerability.get('PkgName', 'unknown')}:{vulnerability.get('InstalledVersion', 'unknown')}",
                            "severity": vulnerability.get("Severity", "LOW"),
                            "description": vulnerability.get("Description", ""),
                            "cve": vulnerability.get("VulnerabilityID", "")
                        })
            return results
    except (json.JSONDecodeError, Exception) as e:
        print(f"Error parsing SCA file {file}: {e}")
        return []

def parse_iac(file):
    if not os.path.exists(file):
        return []
    try:
        with open(file) as f:
            data = json.load(f)
            # Handle case where data is an empty list
            if isinstance(data, list):
                return []
            
            results = []
            
            # Handle Checkov output format
            failed_checks = []
            
            if "check_type" in data and "results" in data:
                # Standard Checkov format: {"check_type": "kubernetes", "results": {"failed_checks": [...], "passed_checks": [...]}}
                failed_checks = data["results"].get("failed_checks", [])
            elif "results" in data and isinstance(data["results"], dict):
                # Alternative format where results is directly a dict
                failed_checks = data["results"].get("failed_checks", [])
            elif "results" in data and isinstance(data["results"], list):
                # Format where results is directly a list of findings
                failed_checks = data["results"]
            elif "failed_checks" in data:
                # Direct failed_checks format
                failed_checks = data["failed_checks"]
            elif isinstance(data, list):
                # Direct list format
                failed_checks = data
            
            # Process failed checks
            for finding in failed_checks:
                if isinstance(finding, dict):
                    # Map severity - Checkov doesn't always provide explicit severity
                    severity = finding.get("severity", "MEDIUM")
                    if not severity or severity == "":
                        # Infer severity from check name or type
                        check_name = finding.get("check_name", "").lower()
                        if any(keyword in check_name for keyword in ["privilege", "root", "admin", "security", "secret"]):
                            severity = "HIGH"
                        else:
                            severity = "MEDIUM"
                    
                    results.append({
                        "type": "iac",
                        "title": finding.get("check_id", "Unknown"),
                        "location": finding.get("file_path", "N/A"),
                        "severity": severity,
                        "description": finding.get("check_name", ""),
                        "resource": finding.get("resource", ""),
                        "line": finding.get("file_line_range", [0])[0] if finding.get("file_line_range") else 0
                    })
            
            return results
    except (json.JSONDecodeError, Exception) as e:
        print(f"Error parsing IaC file {file}: {e}")
        return []

def parse_secrets(file):
    if not os.path.exists(file):
        return []
    try:
        with open(file) as f:
            data = json.load(f)
            if not isinstance(data, list):
                return []
            return [
                {
                    "type": "secrets",
                    "title": finding.get("RuleID", finding.get("Title", "Unknown")),
                    "location": finding.get("File", "N/A"),
                    "severity": "HIGH",
                    "description": finding.get("Description", finding.get("Message", "")),
                    "line": finding.get("StartLine", 0)
                }
                for finding in data
                if isinstance(finding, dict)
            ]
    except (json.JSONDecodeError, Exception) as e:
        print(f"Error parsing Secrets file {file}: {e}")
        return []

def parse_dast(file):
    if not os.path.exists(file):
        return []
    try:
        with open(file) as f:
            data = json.load(f)
            # Handle case where data is an empty list
            if isinstance(data, list):
                return []
            
            results = []
            sites = data.get("site", [])
            if not sites:
                return []
                
            for site in sites:
                if not isinstance(site, dict):
                    continue
                    
                alerts = site.get("alerts", [])
                for alert in alerts:
                    if isinstance(alert, dict):
                        # Map ZAP risk levels to standard severity
                        risk_mapping = {
                            "High": "HIGH",
                            "Medium": "MEDIUM", 
                            "Low": "LOW",
                            "Informational": "INFO"
                        }
                        
                        severity = alert.get("riskdesc", "LOW")
                        if "(" in severity:
                            severity = severity.split("(")[0].strip()
                        severity = risk_mapping.get(severity, "LOW")
                        
                        results.append({
                            "type": "dast",
                            "title": alert.get("name", "Unknown"),
                            "location": alert.get("instances", [{}])[0].get("uri", "N/A") if alert.get("instances") else "N/A",
                            "severity": severity,
                            "description": alert.get("desc", ""),
                            "cwe": alert.get("cweid", ""),
                            "confidence": alert.get("confidence", ""),
                            "solution": alert.get("solution", "")
                        })
            return results
    except (json.JSONDecodeError, Exception) as e:
        print(f"Error parsing DAST file {file}: {e}")
        return []

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
    
    # Parse each type of finding with error handling
    if args.sast:
        sast_findings = parse_sast(args.sast)
        findings.extend(sast_findings)
        print(f"Parsed {len(sast_findings)} SAST findings")
    
    if args.sca:
        sca_findings = parse_sca(args.sca)
        findings.extend(sca_findings)
        print(f"Parsed {len(sca_findings)} SCA findings")
    
    if args.iac:
        iac_findings = parse_iac(args.iac)
        findings.extend(iac_findings)
        print(f"Parsed {len(iac_findings)} IaC findings")
    
    if args.secrets:
        secrets_findings = parse_secrets(args.secrets)
        findings.extend(secrets_findings)
        print(f"Parsed {len(secrets_findings)} Secrets findings")
    
    if args.dast:
        dast_findings = parse_dast(args.dast)
        findings.extend(dast_findings)
        print(f"Parsed {len(dast_findings)} DAST findings")

    # Write findings to JSONL file
    try:
        with open(args.out, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding) + "\n")
        print(f"Successfully merged {len(findings)} findings into {args.out}")
    except Exception as e:
        print(f"Error writing output file {args.out}: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
