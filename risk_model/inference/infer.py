import json
from pathlib import Path
import argparse
from openai import OpenAI
from jinja2 import Template
import os

def load_findings(file_path):
    findings = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))
        print(f"Loaded {len(findings)} findings from {file_path}")
    except Exception as e:
        print(f"Error loading findings.jsonl: {e}")
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
    - owasp: OWASP Top 10 2021 category or 'None'
    - ai_explanation: A short explanation for the finding (1-2 sentences)
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
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
            'owasp': result.get('owasp', 'None'),
            'ai_explanation': result.get('ai_explanation', '')
        }
    except Exception as e:
        print(f"Error querying OpenAI for {finding['title']}: {e}")
        return {'cve': 'Unknown', 'cvss': 0.0, 'epss': 0.0, 'kev': 'No', 'owasp': 'None', 'ai_explanation': ''}

def prioritize_finding(finding):
    cvss = finding.get('cvss', 0.0)
    epss = finding.get('epss', 0.0)
    kev = finding.get('kev', 'No') == 'Yes'
    owasp = finding.get('owasp', 'None') != 'None'

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

def generate_summary(findings):
    high_count = sum(1 for f in findings if f['priority'] == 'High')
    medium_count = sum(1 for f in findings if f['priority'] == 'Medium')
    low_count = sum(1 for f in findings if f['priority'] == 'Low')
    total = len(findings)
    return {'total': total, 'high': high_count, 'medium': medium_count, 'low': low_count}

def generate_html_report(findings, summary, output_file):
    categories = {}
    for f in findings:
        cat = categorize_finding(f)
        categories.setdefault(cat, []).append(f)

    template_str = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
h1, h2 { color: #333; }
table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.high { background-color: #ffcccc; }
.medium { background-color: #fff4cc; }
.low { background-color: #ccffcc; }
.summary { margin-bottom: 30px; }
</style>
</head>
<body>
<h1>Vulnerability Report</h1>
<div class="summary">
<h2>Summary</h2>
<p>Total Findings: {{ summary.total }}</p>
<p>High Priority: {{ summary.high }}</p>
<p>Medium Priority: {{ summary.medium }}</p>
<p>Low Priority: {{ summary.low }}</p>
</div>
{% for category, findings in categories.items() %}
    {% if findings %}
        <h2>{{ category }}</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>CVE</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th>OWASP</th>
                <th>Risk Score</th>
                <th>Priority</th>
                <th>AI Explanation</th>
            </tr>
            {% for finding in findings %}
                <tr class="{{ finding.priority | lower }}">
                    <td>{{ finding.id }}</td>
                    <td>{{ finding.title }}</td>
                    <td>{{ finding.severity }}</td>
                    <td>{{ finding.cve }}</td>
                    <td>{{ "%.2f"|format(finding.cvss) }}</td>
                    <td>{{ "%.2f"|format(finding.epss) }}</td>
                    <td>{{ finding.kev }}</td>
                    <td>{{ finding.owasp }}</td>
                    <td>{{ "%.2f"|format(finding.risk_score) }}</td>
                    <td>{{ finding.priority }}</td>
                    <td>{{ finding.ai_explanation }}</td>
                </tr>
            {% endfor %}
        </table>
    {% endif %}
{% endfor %}
</body>
</html>"""
    template = Template(template_str)
    with open(output_file, 'w') as f:
        f.write(template.render(summary=summary, categories=categories))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts-dir', type=Path, required=True)
    parser.add_argument('--in', dest='input_file', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()

    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    findings = load_findings(args.input_file)

    for finding in findings:
        details = get_cve_details(finding, client)
        finding.update(details)
        finding['priority'] = prioritize_finding(finding)

    summary = generate_summary(findings)

    with open(args.out, 'w') as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    generate_html_report(findings, summary, args.report)

if __name__ == "__main__":
    main()
