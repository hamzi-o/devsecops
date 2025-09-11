import json
import pickle
import pandas as pd
from pathlib import Path
import argparse
from openai import OpenAI
import torch
import os
from jinja2 import Template

def load_findings(file_path):
    findings = []
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip():
                findings.append(json.loads(line))
    return findings

def get_cve_details(finding, client):
    """Use OpenAI to search for CVE, EPSS, KEV, and OWASP Top 10 details."""
    cwe_list = finding.get('cwe', []) if isinstance(finding.get('cwe', []), list) else []
    cwe_str = ', '.join(cwe_list) if cwe_list else 'None'
    prompt = f"""
    Given the following vulnerability finding, search for the corresponding CVE, EPSS score, KEV status, and OWASP Top 10 (2021) category:
    - Type: {finding['type']}
    - Title: {finding['title']}
    - Description: {finding['description']}
    - CWE: {cwe_str}
    
    Return a JSON object with:
    - cve: The relevant CVE ID (e.g., CVE-2018-1000802) or 'Unknown' if none found
    - cvss: CVSS score (e.g., 9.8) or 0.0 if unknown
    - epss: EPSS score (e.g., 0.0096) or 0.0 if unknown
    - kev: 'Yes' or 'No' indicating KEV status
    - owasp: OWASP Top 10 2021 category (e.g., A08:2021) or 'None'
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert with access to CVE, EPSS, and OWASP Top 10 data."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        result = json.loads(response.choices[0].message.content)
        return {
            'cve': result.get('cve', 'Unknown'),
            'cvss': float(result.get('cvss', 0.0)),
            'epss': float(result.get('epss', 0.0)),
            'kev': result.get('kev', 'No'),
            'owasp': result.get('owasp', 'None')
        }
    except Exception as e:
        print(f"Error querying OpenAI for {finding['title']}: {e}")
        return {
            'cve': 'Unknown',
            'cvss': 0.0,
            'epss': 0.0,
            'kev': 'No',
            'owasp': 'None'
        }

def categorize_finding(finding):
    """Categorize findings into App, Packages, Infrastructure, or Dependencies."""
    location = finding.get('location', '').lower()
    finding_type = finding.get('type', '').lower()
    if finding_type == 'iac':
        return 'Infrastructure'
    elif finding_type == 'sca':
        return 'Packages'
    elif location.startswith('venv/lib') or location.startswith('site-packages'):
        return 'Dependencies'
    else:
        return 'App'

def prioritize_findings(findings):
    """Prioritize findings based on CVSS, EPSS, KEV, CWE, and OWASP."""
    for finding in findings:
        cvss = finding['cvss']
        epss = finding['epss']
        kev = finding['kev'] == 'Yes'
        cwe_list = finding.get('cwe', []) if isinstance(finding.get('cwe', []), list) else []
        owasp = finding['owasp'] != 'None'
        
        # Prioritization logic
        if kev or cvss >= 9.0 or epss > 0.5 or ('CWE-502' in cwe_list and owasp):
            finding['priority'] = 'High'
        elif cvss >= 7.0 or epss > 0.1 or ('CWE-502' in cwe_list and cvss >= 4.0):
            finding['priority'] = 'Medium'
        else:
            finding['priority'] = 'Low'
    return findings

def generate_summary(findings, client):
    """Generate a summary of main issues using OpenAI."""
    high_priority = [f for f in findings if f['priority'] == 'High']
    medium_priority = [f for f in findings if f['priority'] == 'Medium']
    summary_prompt = f"""
    Summarize the main security issues from the following findings:
    - High Priority ({len(high_priority)}): {json.dumps(high_priority, indent=2)}
    - Medium Priority ({len(medium_priority)}): {json.dumps(medium_priority, indent=2)}
    - Total Findings: {len(findings)}
    
    Provide a concise summary (2-3 sentences) of the main issues, focusing on high and medium priority vulnerabilities across App, Packages, Infrastructure, and Dependencies categories. Include recommendations for remediation.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert summarizing vulnerability findings."},
                {"role": "user", "content": summary_prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error generating summary: {e}")
        return "No high or medium priority vulnerabilities found. Review low priority findings in App, Packages, Infrastructure, and Dependencies categories for potential issues and ensure secure coding practices."

def generate_html_report(findings, summary, output_file):
    """Generate HTML report with categorized tables for each category."""
    categories = ['App', 'Packages', 'Infrastructure', 'Dependencies']
    categorized_findings = {cat: {'High': [], 'Medium': [], 'Low': []} for cat in categories}
    
    for finding in findings:
        category = categorize_finding(finding)
        priority = finding['priority']
        categorized_findings[category][priority].append(finding)
    
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            h1, h2, h3 { color: #333; }
            .summary { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <h1>Security Report</h1>
        <div class="summary">
            <h2>Summary of Main Issues</h2>
            <p>{{ summary }}</p>
        </div>
        
        {% for category in categories %}
        <h2>{{ category }} Category</h2>
        
        <h3>High Priority Vulnerabilities ({{ categorized_findings[category].High|length }})</h3>
        {% if categorized_findings[category].High %}
        <table>
            <tr>
                <th>ID</th><th>Type</th><th>Location</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Risk Score</th><th>OWASP Top 10</th><th>CVE</th>
            </tr>
            {% for finding in categorized_findings[category].High %}
            <tr>
                <td>{{ loop.index0 }}</td>
                <td>{{ finding.type }}</td>
                <td>{{ finding.location }}</td>
                <td>{{ finding.cvss }}</td>
                <td>{{ finding.epss }}</td>
                <td>{{ finding.kev }}</td>
                <td>{{ finding.risk_score }}</td>
                <td>{{ finding.owasp }}</td>
                <td>{{ finding.cve }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No high priority vulnerabilities in {{ category }} category.</p>
        {% endif %}
        
        <h3>Medium Priority Vulnerabilities ({{ categorized_findings[category].Medium|length }})</h3>
        {% if categorized_findings[category].Medium %}
        <table>
            <tr>
                <th>ID</th><th>Type</th><th>Location</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Risk Score</th><th>OWASP Top 10</th><th>CVE</th>
            </tr>
            {% for finding in categorized_findings[category].Medium %}
            <tr>
                <td>{{ loop.index0 }}</td>
                <td>{{ finding.type }}</td>
                <td>{{ finding.location }}</td>
                <td>{{ finding.cvss }}</td>
                <td>{{ finding.epss }}</td>
                <td>{{ finding.kev }}</td>
                <td>{{ finding.risk_score }}</td>
                <td>{{ finding.owasp }}</td>
                <td>{{ finding.cve }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No medium priority vulnerabilities in {{ category }} category.</p>
        {% endif %}
        
        <h3>Low Priority Vulnerabilities ({{ categorized_findings[category].Low|length }})</h3>
        {% if categorized_findings[category].Low %}
        <table>
            <tr>
                <th>ID</th><th>Type</th><th>Location</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Risk Score</th><th>OWASP Top 10</th><th>CVE</th>
            </tr>
            {% for finding in categorized_findings[category].Low %}
            <tr>
                <td>{{ loop.index0 }}</td>
                <td>{{ finding.type }}</td>
                <td>{{ finding.location }}</td>
                <td>{{ finding.cvss }}</td>
                <td>{{ finding.epss }}</td>
                <td>{{ finding.kev }}</td>
                <td>{{ finding.risk_score }}</td>
                <td>{{ finding.owasp }}</td>
                <td>{{ finding.cve }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No low priority vulnerabilities in {{ category }} category.</p>
        {% endif %}
        {% endfor %}
    </body>
    </html>
    """
    template = Template(template_str)
    with open(output_file, 'w') as f:
        f.write(template.render(
            summary=summary,
            categories=categories,
            categorized_findings=categorized_findings
        ))

def main():
    parser = argparse.ArgumentParser(description="Run AI inference on findings")
    parser.add_argument('--artifacts-dir', type=Path, required=True, help="Directory with scaler.pkl, best_params.pkl, vuln_prioritizer_checkpoint.pt")
    parser.add_argument('--in', dest='input_file', type=Path, required=True, help="Input JSONL file with findings")
    parser.add_argument('--out', type=Path, required=True, help="Output JSONL file with enriched findings")
    parser.add_argument('--report', type=Path, required=True, help="Output HTML report file")
    args = parser.parse_args()

    # Initialize OpenAI client
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    client = OpenAI(api_key=api_key)

    # Load findings
    findings = load_findings(args.input_file)

    # Load ML model components
    scaler = pickle.load(open(args.artifacts_dir / "scaler.pkl", "rb"))
    best_params = pickle.load(open(args.artifacts_dir / "best_params.pkl", "rb"))
    model = torch.load(args.artifacts_dir / "vuln_prioritizer_checkpoint.pt")

    # Enrich findings with CVE, EPSS, KEV, and OWASP
    enriched_findings = []
    for finding in findings:
        cve_details = get_cve_details(finding, client)
        finding.update(cve_details)
        
        # Prepare features for ML model
        severity = finding.get('severity', 'LOW').lower()
        features = [
            float(severity == 'high'),
            float(severity == 'medium'),
            float(severity == 'low'),
            finding['cvss'],
            finding['epss'],
            float(finding['kev'] == 'Yes'),
            float(finding['owasp'] != 'None'),
            float('CWE-502' in (finding.get('cwe', []) if isinstance(finding.get('cwe', []), list) else []))
        ]
        features = scaler.transform([features])[0]
        
        # Predict risk score
        try:
            model.eval()
            with torch.no_grad():
                risk_score = model(torch.tensor(features, dtype=torch.float32)).item()
        except Exception as e:
            print(f"Error predicting risk score for {finding['title']}: {e}")
            # Fallback: Weighted combination of CVSS, EPSS, KEV, and OWASP
            risk_score = (finding['cvss'] * 0.4 + finding['epss'] * 100 * 0.3 +
                         (1.0 if finding['kev'] == 'Yes' else 0.0) * 0.2 +
                         (1.0 if finding['owasp'] != 'None' else 0.0) * 0.1)
        finding['risk_score'] = round(max(0.0, min(risk_score, 10.0)), 4)
        
        enriched_findings.append(finding)

    # Prioritize findings
    enriched_findings = prioritize_findings(enriched_findings)

    # Generate summary
    summary = generate_summary(enriched_findings, client)

    # Save enriched findings
    with open(args.out, 'w') as f:
        for finding in enriched_findings:
            f.write(json.dumps(finding) + '\n')

    # Generate HTML report
    generate_html_report(enriched_findings, summary, args.report)

if __name__ == "__main__":
    main()
