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
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))
    except Exception as e:
        print(f"Error loading findings.jsonl: {e}")
    # Add ZAP results
    zap_file = Path('zap-report.json')
    if zap_file.exists():
        try:
            with open(zap_file, 'r') as f:
                zap_data = json.load(f)
                for alert in zap_data.get('site', [{}])[0].get('alerts', []):
                    findings.append({
                        'id': alert.get('alertRef', 'Unknown'),
                        'type': 'dast',
                        'title': alert.get('name', 'Unknown'),
                        'description': alert.get('desc', ''),
                        'severity': alert.get('riskdesc', 'LOW').split(' ')[0].upper(),
                        'cwe': [f"CWE-{alert.get('cweid', '0')}"] if alert.get('cweid') else [],
                        'location': alert.get('url', ''),
                        'category': 'App'
                    })
        except Exception as e:
            print(f"Error loading zap-report.json: {e}")
    else:
        print("zap-report.json not found")
    # Add Checkov results
    checkov_file = Path('checkov-report.json')
    if checkov_file.exists():
        try:
            with open(checkov_file, 'r') as f:
                checkov_data = json.load(f)
                for result in checkov_data.get('results', {}).get('failed_checks', []):
                    findings.append({
                        'id': result.get('check_id', 'Unknown'),
                        'type': 'iac',
                        'title': result.get('check_name', 'Unknown'),
                        'description': result.get('description', ''),
                        'severity': result.get('severity', 'LOW').upper(),
                        'cwe': result.get('cwe', []),
                        'location': result.get('file_path', ''),
                        'category': 'Infrastructure'
                    })
        except Exception as e:
            print(f"Error loading checkov-report.json: {e}")
    else:
        print("checkov-report.json not found")
    return findings

def get_cve_details(finding, client):
    prompt = f"""
    Given the following vulnerability finding, search for the corresponding CVE, EPSS score, KEV status, CVSS score, and OWASP Top 10 (2021) category:
    - Type: {finding['type']}
    - Title: {finding['title']}
    - Description: {finding['description']}
    - CWE: {finding.get('cwe', [])}
    
    Return a JSON object with:
    - cve: The relevant CVE ID or 'Unknown'
    - cvss: CVSS score (0.0 to 10.0) or 0.0 if unknown
    - epss: EPSS score (0.0 to 1.0) or 0.0 if unknown
    - kev: 'Yes' or 'No'
    - owasp: OWASP Top 10 2021 category (e.g., 'A01:2021-Broken Access Control') or 'None'
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
        print(f"OpenAI response for {finding['title']}: {result}")
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
    location = finding.get('location', '').lower()
    finding_type = finding.get('type', '').lower()
    if finding_type == 'iac':
        return 'Infrastructure'
    elif finding_type == 'sca':
        return 'Packages'
    elif finding_type == 'dast':
        return 'App'
    elif 'venv' in location or 'site-packages' in location:
        return 'Dependencies'
    else:
        return 'App'

def prioritize_finding(finding):
    cvss = finding['cvss']
    epss = finding['epss']
    kev = finding['kev'] == 'Yes'
    owasp = finding['owasp'] != 'None'
    
    if cvss == 0.0:
        finding['risk_score'] = 0.0
        return 'Low'
    
    score = cvss * 0.4 + epss * 100 * 0.3 + (1 if kev else 0) * 0.2 + (1 if owasp else 0) * 0.1
    finding['risk_score'] = round(min(score, 10.0), 2)
    
    if kev or cvss >= 9.0 or epss > 0.5 or (owasp and cvss >= 7.0):
        return 'High'
    elif cvss >= 7.0 or epss > 0.1 or owasp:
        return 'Medium'
    else:
        return 'Low'

def generate_summary(findings, client):
    high_count = sum(1 for f in findings if f['priority'] == 'High')
    medium_count = sum(1 for f in findings if f['priority'] == 'Medium')
    low_count = sum(1 for f in findings if f['priority'] == 'Low')
    
    prompt = f"""
    Generate a concise summary paragraph (3-5 sentences) for a vulnerability report with {len(findings)} total findings: {high_count} High, {medium_count} Medium, {low_count} Low priority.
    Highlight main issues across categories (App, Packages, Infrastructure, Dependencies), focusing on high/medium risks with CVE, OWASP, EPSS, KEV mentions, and suggest remediation.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300
        )
        print(f"Summary response: {response.choices[0].message.content}")
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error generating summary: {e}")
        return f"The report contains {len(findings)} findings: {high_count} High, {medium_count} Medium, {low_count} Low priority. Focus on high-priority issues for immediate remediation."

def generate_html_report(findings, summary, output_file):
    categories = {
        'App': {'High': [], 'Medium': [], 'Low': []},
        'Packages': {'High': [], 'Medium': [], 'Low': []},
        'Infrastructure': {'High': [], 'Medium': [], 'Low': []},
        'Dependencies': {'High': [], 'Medium': [], 'Low': []}
    }
    
    for finding in findings:
        category = categorize_finding(finding)
        priority = finding['priority']
        categories[category][priority].append(finding)
    
    template_str = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2, h3 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .summary { margin-bottom: 30px; }
        </style>
    </head>
    <body>
        <h1>Security Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p>{{ summary }}</p>
        </div>
        
        {% for category, priorities in categories.items() %}
            <h2>{{ category }}</h2>
            
            {% for priority, priority_findings in priorities.items() %}
                <h3>{{ priority }} Priority</h3>
                {% if priority_findings %}
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Type</th>
                            <th>Title</th>
                            <th>Location</th>
                            <th>CVE</th>
                            <th>CVSS</th>
                            <th>EPSS</th>
                            <th>KEV</th>
                            <th>OWASP Top 10</th>
                            <th>Risk Score</th>
                            <th>Priority</th>
                            <th>Description</th>
                        </tr>
                        {% for finding in priority_findings %}
                            <tr>
                                <td>{{ finding.id }}</td>
                                <td>{{ finding.type }}</td>
                                <td>{{ finding.title }}</td>
                                <td>{{ finding.location }}</td>
                                <td>{{ finding.cve }}</td>
                                <td>{{ finding.cvss }}</td>
                                <td>{{ finding.epss }}</td>
                                <td>{{ finding.kev }}</td>
                                <td>{{ finding.owasp }}</td>
                                <td>{{ finding.risk_score }}</td>
                                <td>{{ finding.priority }}</td>
                                <td>{{ finding.description }}</td>
                            </tr>
                        {% endfor %}
                    </table>
                {% else %}
                    <p>No {{ priority.lower() }} priority vulnerabilities in {{ category }} category.</p>
                {% endif %}
            {% endfor %}
        {% endfor %}
    </body>
    </html>
    """
    template = Template(template_str)
    with open(output_file, 'w') as f:
        f.write(template.render(summary=summary, categories=categories))

def main():
    parser = argparse.ArgumentParser(description="Run AI inference on findings")
    parser.add_argument('--artifacts-dir', type=Path, required=True, help="Directory with scaler.pkl, best_params.pkl, vuln_prioritizer_checkpoint.pt")
    parser.add_argument('--in', dest='input_file', type=Path, required=True, help="Input JSONL file with findings")
    parser.add_argument('--out', type=Path, required=True, help="Output JSONL file with enriched findings")
    parser.add_argument('--report', type=Path, required=True, help="Output HTML report file")
    args = parser.parse_args()

    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    findings = load_findings(args.input_file)
    print(f"Loaded {len(findings)} findings")
    for finding in findings:
        details = get_cve_details(finding, client)
        finding.update(details)
        finding['priority'] = prioritize_finding(finding)

    summary = generate_summary(findings, client)
    with open(args.out, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")
    generate_html_report(findings, summary, args.report)

if __name__ == "__main__":
    main()
