import json
from pathlib import Path
import argparse
from openai import OpenAI
from jinja2 import Template
import os
import time
from typing import Dict, List, Any

def load_findings(file_path: Path) -> List[Dict[str, Any]]:
    """Load findings from JSONL file."""
    findings = []
    try:
        with open(file_path, 'r') as f:
            for idx, line in enumerate(f, 1):
                if line.strip():
                    finding = json.loads(line)
                    finding['id'] = f"F{idx:04d}"  # Generate finding ID
                    findings.append(finding)
        print(f"Loaded {len(findings)} findings from {file_path}")
    except Exception as e:
        print(f"Error loading findings.jsonl: {e}")
    return findings

def get_enhanced_analysis(finding: Dict[str, Any], client: OpenAI) -> Dict[str, Any]:
    """Get enhanced analysis including CVE, EPSS, CVSS, KEV, and OWASP mapping."""
    
    # Create a detailed prompt with more context
    prompt = f"""
    Analyze this security finding and provide detailed vulnerability intelligence:
    
    Finding Details:
    - Type: {finding['type']}
    - Title: {finding['title']}
    - Description: {finding.get('description', 'N/A')}
    - Location: {finding.get('location', 'N/A')}
    - Severity: {finding.get('severity', 'N/A')}
    - CWE: {finding.get('cwe', 'N/A')}
    - CVE: {finding.get('cve', 'N/A')}
    
    Please provide comprehensive analysis in JSON format:
    {{
        "cve": "Most relevant CVE ID or 'N/A' if none applicable",
        "cvss_score": "CVSS v3.1 base score (0.0-10.0) as float",
        "epss_score": "EPSS probability score (0.0-1.0) as float", 
        "kev_status": "YES if in CISA KEV catalog, NO otherwise",
        "owasp_2021": "OWASP Top 10 2021 category (A01-A10) or 'N/A'",
        "exploit_available": "YES if public exploits exist, NO otherwise",
        "remediation_effort": "LOW/MEDIUM/HIGH based on fix complexity",
        "business_impact": "Brief description of potential business impact",
        "technical_details": "Technical explanation of the vulnerability (2-3 sentences)",
        "remediation_guidance": "Specific actionable remediation steps",
        "confidence_level": "HIGH/MEDIUM/LOW based on analysis confidence"
    }}
    
    Be specific and accurate. If information is not available or uncertain, use 'N/A' or appropriate defaults.
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst with expertise in vulnerability assessment, CVSS scoring, EPSS analysis, and threat intelligence. Provide accurate, actionable security analysis."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3  # Lower temperature for more consistent results
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Validate and sanitize the response
        enhanced_data = {
            'cve': result.get('cve', 'N/A'),
            'cvss_score': float(result.get('cvss_score', 0.0)),
            'epss_score': float(result.get('epss_score', 0.0)),
            'kev_status': result.get('kev_status', 'NO'),
            'owasp_2021': result.get('owasp_2021', 'N/A'),
            'exploit_available': result.get('exploit_available', 'NO'),
            'remediation_effort': result.get('remediation_effort', 'MEDIUM'),
            'business_impact': result.get('business_impact', 'To be assessed'),
            'technical_details': result.get('technical_details', 'No details available'),
            'remediation_guidance': result.get('remediation_guidance', 'Review and address this finding'),
            'confidence_level': result.get('confidence_level', 'MEDIUM')
        }
        
        return enhanced_data
        
    except Exception as e:
        print(f"Error querying OpenAI for {finding['title']}: {e}")
        return {
            'cve': 'N/A',
            'cvss_score': 0.0,
            'epss_score': 0.0,
            'kev_status': 'NO',
            'owasp_2021': 'N/A',
            'exploit_available': 'NO',
            'remediation_effort': 'MEDIUM',
            'business_impact': 'Assessment needed',
            'technical_details': 'Analysis unavailable due to API error',
            'remediation_guidance': 'Manual review required',
            'confidence_level': 'LOW'
        }

def calculate_risk_score(finding: Dict[str, Any]) -> tuple[float, str]:
    """Calculate comprehensive risk score and priority."""
    
    # Base scores
    cvss = finding.get('cvss_score', 0.0)
    epss = finding.get('epss_score', 0.0)
    
    # Boolean factors
    is_kev = finding.get('kev_status', 'NO') == 'YES'
    has_exploit = finding.get('exploit_available', 'NO') == 'YES'
    is_owasp = finding.get('owasp_2021', 'N/A') != 'N/A'
    
    # Remediation effort factor (inverse - higher effort = higher risk)
    effort_multiplier = {
        'LOW': 0.8,
        'MEDIUM': 1.0,
        'HIGH': 1.3
    }.get(finding.get('remediation_effort', 'MEDIUM'), 1.0)
    
    # Finding type weight
    type_weights = {
        'dast': 1.2,  # Runtime vulnerabilities are more critical
        'sast': 1.1,  # Source code issues
        'secrets': 1.3,  # Exposed secrets are critical
        'sca': 1.0,   # Dependency vulnerabilities
        'iac': 0.9    # Infrastructure misconfigurations
    }
    type_weight = type_weights.get(finding.get('type', ''), 1.0)
    
    # Calculate base risk score
    if cvss == 0.0:
        # No CVSS available, use heuristic based on other factors
        base_score = 5.0 if (is_kev or has_exploit or is_owasp) else 3.0
    else:
        base_score = cvss
    
    # Apply modifiers
    risk_score = base_score * type_weight * effort_multiplier
    
    # Add bonus points for critical factors
    if is_kev:
        risk_score += 2.0
    if has_exploit:
        risk_score += 1.5
    if epss > 0.5:
        risk_score += 1.0
    elif epss > 0.1:
        risk_score += 0.5
    if is_owasp and cvss >= 7.0:
        risk_score += 1.0
    
    # Cap at 10.0
    risk_score = min(risk_score, 10.0)
    
    # Determine priority
    if risk_score >= 8.5 or is_kev or (cvss >= 9.0) or (has_exploit and cvss >= 7.0):
        priority = 'Critical'
    elif risk_score >= 7.0 or (cvss >= 7.0) or (epss > 0.3) or (is_owasp and cvss >= 6.0):
        priority = 'High'
    elif risk_score >= 4.0 or (cvss >= 4.0) or (epss > 0.1) or is_owasp:
        priority = 'Medium'
    else:
        priority = 'Low'
    
    return round(risk_score, 2), priority

def categorize_finding(finding: Dict[str, Any]) -> str:
    """Categorize finding by type and location."""
    finding_type = finding.get('type', '').lower()
    location = finding.get('location', '').lower()
    
    if finding_type == 'dast':
        return 'App'
    elif finding_type == 'secrets':
        return 'App'  # Secrets are app-related
    elif finding_type == 'sast':
        return 'App'
    elif finding_type == 'iac':
        return 'Infrastructure'
    elif finding_type == 'sca':
        if 'venv' in location or 'site-packages' in location or 'node_modules' in location:
            return 'Dependencies'
        else:
            return 'Packages'
    else:
        return 'Other'

def generate_executive_summary(findings: List[Dict[str, Any]]) -> str:
    """Generate executive summary paragraph."""
    
    total = len(findings)
    if total == 0:
        return "No security findings were identified in this assessment."
    
    # Count by priority
    priority_counts = {}
    category_counts = {}
    owasp_findings = 0
    kev_findings = 0
    
    for finding in findings:
        priority = finding.get('priority', 'Unknown')
        category = finding.get('category', 'Unknown')
        
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        
        if finding.get('owasp_2021', 'N/A') != 'N/A':
            owasp_findings += 1
        if finding.get('kev_status', 'NO') == 'YES':
            kev_findings += 1
    
    # Build summary
    summary_parts = []
    summary_parts.append(f"This security assessment identified {total} total findings across the application and infrastructure.")
    
    if priority_counts.get('Critical', 0) > 0:
        summary_parts.append(f"{priority_counts['Critical']} critical vulnerabilities require immediate attention.")
    
    if priority_counts.get('High', 0) > 0:
        summary_parts.append(f"{priority_counts['High']} high-priority issues should be addressed within the next sprint.")
    
    if kev_findings > 0:
        summary_parts.append(f"{kev_findings} findings are listed in CISA's Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation in the wild.")
    
    if owasp_findings > 0:
        summary_parts.append(f"{owasp_findings} findings correspond to OWASP Top 10 2021 categories, representing common web application security risks.")
    
    # Category breakdown
    if category_counts:
        category_list = [f"{count} in {cat.lower()}" for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)]
        summary_parts.append(f"Issues were distributed as follows: {', '.join(category_list)}.")
    
    summary_parts.append("Immediate focus should be placed on critical and high-priority findings, particularly those with known exploits or CISA KEV listings.")
    
    return " ".join(summary_parts)

def generate_html_report(findings: List[Dict[str, Any]], summary: Dict[str, int], output_file: Path):
    """Generate comprehensive HTML report."""
    
    # Categorize and sort findings
    categories = {}
    for finding in findings:
        cat = finding.get('category', 'Other')
        categories.setdefault(cat, []).append(finding)
    
    # Sort categories (App first, then alphabetically)
    category_order = ['App', 'Infrastructure', 'Dependencies', 'Packages', 'Other']
    sorted_categories = {}
    for cat in category_order:
        if cat in categories:
            # Sort findings within category by priority (Critical > High > Medium > Low)
            priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            categories[cat].sort(key=lambda x: (
                priority_order.get(x.get('priority', 'Low'), 4),
                -x.get('risk_score', 0)
            ))
            sorted_categories[cat] = categories[cat]
    
    # Add any remaining categories
    for cat, findings_list in categories.items():
        if cat not in sorted_categories:
            priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            findings_list.sort(key=lambda x: (
                priority_order.get(x.get('priority', 'Low'), 4),
                -x.get('risk_score', 0)
            ))
            sorted_categories[cat] = findings_list
    
    # Generate executive summary
    executive_summary = generate_executive_summary(findings)
    
    template_str = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f8f9fa;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .executive-summary { 
            background: #ecf0f1; 
            padding: 20px; 
            border-radius: 5px; 
            margin: 20px 0; 
            border-left: 4px solid #3498db;
        }
        .summary-stats { 
            display: flex; 
            justify-content: space-around; 
            margin: 20px 0; 
            flex-wrap: wrap;
        }
        .stat-box { 
            text-align: center; 
            padding: 15px; 
            border-radius: 5px; 
            min-width: 120px; 
            margin: 5px;
        }
        .stat-box h3 { margin: 0; font-size: 2em; }
        .stat-box p { margin: 5px 0 0 0; font-weight: bold; }
        .critical-stat { background: #e74c3c; color: white; }
        .high-stat { background: #e67e22; color: white; }
        .medium-stat { background: #f39c12; color: white; }
        .low-stat { background: #27ae60; color: white; }
        .total-stat { background: #3498db; color: white; }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            font-size: 14px;
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px 8px; 
            text-align: left; 
            vertical-align: top;
        }
        th { 
            background: #34495e; 
            color: white; 
            font-weight: bold;
            position: sticky;
            top: 0;
        }
        .critical { background: #fdf2f2; border-left: 4px solid #e74c3c; }
        .high { background: #fef9f5; border-left: 4px solid #e67e22; }
        .medium { background: #fefbf3; border-left: 4px solid #f39c12; }
        .low { background: #f2fef5; border-left: 4px solid #27ae60; }
        
        .priority-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .priority-critical { background: #e74c3c; color: white; }
        .priority-high { background: #e67e22; color: white; }
        .priority-medium { background: #f39c12; color: white; }
        .priority-low { background: #27ae60; color: white; }
        
        .cve-link { color: #3498db; text-decoration: none; }
        .cve-link:hover { text-decoration: underline; }
        
        .kev-yes { color: #e74c3c; font-weight: bold; }
        .kev-no { color: #7f8c8d; }
        
        .confidence-high { color: #27ae60; font-weight: bold; }
        .confidence-medium { color: #f39c12; font-weight: bold; }
        .confidence-low { color: #e74c3c; font-weight: bold; }
        
        .technical-details { 
            max-width: 300px; 
            word-wrap: break-word; 
            font-size: 13px;
        }
        .remediation { 
            max-width: 250px; 
            word-wrap: break-word; 
            font-size: 13px;
        }
        
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .summary-stats { flex-direction: column; }
            table { font-size: 12px; }
            th, td { padding: 8px 4px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Assessment Report</h1>
        
        <div class="executive-summary">
            <h3>Executive Summary</h3>
            <p>{{ executive_summary }}</p>
        </div>
        
        <div class="summary-stats">
            <div class="stat-box total-stat">
                <h3>{{ summary.total }}</h3>
                <p>Total Findings</p>
            </div>
            <div class="stat-box critical-stat">
                <h3>{{ summary.critical }}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-box high-stat">
                <h3>{{ summary.high }}</h3>
                <p>High Priority</p>
            </div>
            <div class="stat-box medium-stat">
                <h3>{{ summary.medium }}</h3>
                <p>Medium Priority</p>
            </div>
            <div class="stat-box low-stat">
                <h3>{{ summary.low }}</h3>
                <p>Low Priority</p>
            </div>
        </div>

        {% for category, findings in categories.items() %}
            {% if findings %}
                <h2>{{ category }} ({{ findings|length }} findings)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Priority</th>
                            <th>Title</th>
                            <th>Type</th>
                            <th>Location</th>
                            <th>CVE</th>
                            <th>CVSS</th>
                            <th>EPSS</th>
                            <th>KEV</th>
                            <th>OWASP</th>
                            <th>Risk Score</th>
                            <th>Technical Details</th>
                            <th>Remediation</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in findings %}
                            <tr class="{{ finding.priority | lower }}">
                                <td><strong>{{ finding.id }}</strong></td>
                                <td>
                                    <span class="priority-badge priority-{{ finding.priority | lower }}">
                                        {{ finding.priority }}
                                    </span>
                                </td>
                                <td><strong>{{ finding.title }}</strong></td>
                                <td>{{ finding.type | upper }}</td>
                                <td style="max-width: 200px; word-wrap: break-word; font-size: 12px;">{{ finding.location }}</td>
                                <td>
                                    {% if finding.cve != 'N/A' %}
                                        <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ finding.cve }}" 
                                           class="cve-link" target="_blank">{{ finding.cve }}</a>
                                    {% else %}
                                        <span style="color: #7f8c8d;">N/A</span>
                                    {% endif %}
                                </td>
                                <td>{{ "%.1f"|format(finding.cvss_score) }}</td>
                                <td>{{ "%.3f"|format(finding.epss_score) }}</td>
                                <td class="{% if finding.kev_status == 'YES' %}kev-yes{% else %}kev-no{% endif %}">
                                    {{ finding.kev_status }}
                                </td>
                                <td>{{ finding.owasp_2021 }}</td>
                                <td><strong>{{ "%.2f"|format(finding.risk_score) }}</strong></td>
                                <td class="technical-details">{{ finding.technical_details }}</td>
                                <td class="remediation">{{ finding.remediation_guidance }}</td>
                                <td class="confidence-{{ finding.confidence_level | lower }}">
                                    {{ finding.confidence_level }}
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% endif %}
        {% endfor %}
        
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px;">
            <p><strong>Report Legend:</strong></p>
            <ul style="list-style: none; padding: 0;">
                <li>🔴 <strong>Critical:</strong> Immediate action required - active exploitation likely</li>
                <li>🟠 <strong>High:</strong> Address within current sprint - significant risk</li>
                <li>🟡 <strong>Medium:</strong> Plan remediation in next release cycle</li>
                <li>🟢 <strong>Low:</strong> Address as time permits - low immediate risk</li>
            </ul>
            <p><strong>EPSS:</strong> Exploit Prediction Scoring System (probability of exploitation in next 30 days)<br>
               <strong>KEV:</strong> CISA Known Exploited Vulnerabilities catalog<br>
               <strong>OWASP:</strong> OWASP Top 10 2021 Web Application Security Risks</p>
        </div>
    </div>
</body>
</html>"""

    template = Template(template_str)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(template.render(
            executive_summary=executive_summary,
            summary=summary, 
            categories=sorted_categories
        ))

def main():
    parser = argparse.ArgumentParser(description="Enhanced Security Finding Analysis with AI")
    parser.add_argument('--artifacts-dir', type=Path, required=True, help="Artifacts directory")
    parser.add_argument('--in', dest='input_file', type=Path, required=True, help="Input JSONL file")
    parser.add_argument('--out', type=Path, required=True, help="Output enriched JSONL file")
    parser.add_argument('--report', type=Path, required=True, help="Output HTML report file")
    parser.add_argument('--max-requests', type=int, default=100, help="Maximum API requests")
    args = parser.parse_args()

    # Check for OpenAI API key
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    client = OpenAI(api_key=api_key)

    # Load findings
    findings = load_findings(args.input_file)
    
    if not findings:
        print("No findings to process")
        return

    print(f"Processing {len(findings)} findings with AI analysis...")

    # Process each finding with AI analysis
    processed_count = 0
    for idx, finding in enumerate(findings, 1):
        if processed_count >= args.max_requests:
            print(f"Reached maximum API requests limit ({args.max_requests})")
            break
            
        print(f"Processing finding {idx}/{len(findings)}: {finding.get('title', 'Unknown')}")
        
        # Get AI analysis
        analysis = get_enhanced_analysis(finding, client)
        finding.update(analysis)
        
        # Calculate risk score and priority
        risk_score, priority = calculate_risk_score(finding)
        finding['risk_score'] = risk_score
        finding['priority'] = priority
        
        # Categorize finding
        finding['category'] = categorize_finding(finding)
        
        processed_count += 1
        
        # Rate limiting - be nice to the API
        if idx % 10 == 0:
            time.sleep(1)

    # Generate summary statistics
    summary = {
        'total': len(findings),
        'critical': sum(1 for f in findings if f.get('priority') == 'Critical'),
        'high': sum(1 for f in findings if f.get('priority') == 'High'),
        'medium': sum(1 for f in findings if f.get('priority') == 'Medium'),
        'low': sum(1 for f in findings if f.get('priority') == 'Low'),
    }

    print(f"\n📊 Summary: {summary['total']} total findings")
    print(f"   🔴 Critical: {summary['critical']}")
    print(f"   🟠 High: {summary['high']}")
    print(f"   🟡 Medium: {summary['medium']}")
    print(f"   🟢 Low: {summary['low']}")

    # Save enriched findings
    with open(args.out, 'w', encoding='utf-8') as f:
        for finding in findings:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")

    # Generate HTML report
    generate_html_report(findings, summary, args.report)
    
    print(f"✅ Analysis complete!")
    print(f"   📄 Enriched findings: {args.out}")
    print(f"   📊 HTML report: {args.report}")

if __name__ == "__main__":
    main()
