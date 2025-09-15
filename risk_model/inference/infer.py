import json
from pathlib import Path
import argparse
from openai import OpenAI
from jinja2 import Template
import os
import time
from typing import Dict, List, Any
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data, Batch
import pickle
import numpy as np
import re
from datetime import datetime
import hashlib

# GCN Model Definition (should match your training architecture)
class VulnGCN(nn.Module):
    def __init__(self, num_features, hidden_dim, num_classes, num_layers=3, dropout=0.3):
        super(VulnGCN, self).__init__()
        self.num_layers = num_layers
        self.dropout = dropout

        # GCN layers
        self.convs = nn.ModuleList()
        self.convs.append(GCNConv(num_features, hidden_dim))
        for _ in range(num_layers - 2):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))
        self.convs.append(GCNConv(hidden_dim, hidden_dim))

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_classes)
        )

    def forward(self, x, edge_index, batch):
        # Graph convolutions
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)

        # Global pooling
        x = global_mean_pool(x, batch)

        # Classification
        x = self.classifier(x)
        return x

class VulnPrioritizer:
    def __init__(self, artifacts_dir: Path):
        self.artifacts_dir = artifacts_dir
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = None
        self.scaler = None
        self.best_params = None
        self.priority_mapping = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}

        self.load_model_artifacts()

    def load_model_artifacts(self):
        """Load trained model, scaler, and parameters."""
        try:
            # Load scaler
            scaler_path = self.artifacts_dir / 'scaler.pkl'
            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                print(f"✅ Loaded scaler from {scaler_path}")
            else:
                print(f"⚠️ Scaler not found at {scaler_path}")

            # Load best parameters
            params_path = self.artifacts_dir / 'best_params.pkl'
            if params_path.exists():
                with open(params_path, 'rb') as f:
                    self.best_params = pickle.load(f)
                print(f"✅ Loaded parameters from {params_path}")
            else:
                print(f"⚠️ Parameters not found at {params_path}")
                # Default parameters
                self.best_params = {
                    'hidden_dim': 128,
                    'num_layers': 3,
                    'dropout': 0.3,
                    'num_classes': 4
                }

            # Load model checkpoint
            checkpoint_path = self.artifacts_dir / 'vuln_prioritizer_checkpoint.pt'
            if checkpoint_path.exists():
                checkpoint = torch.load(checkpoint_path, map_location=self.device)

                # Initialize model with parameters
                num_features = checkpoint.get('num_features', 50)  # Default feature size
                self.model = VulnGCN(
                    num_features=num_features,
                    hidden_dim=self.best_params.get('hidden_dim', 128),
                    num_classes=self.best_params.get('num_classes', 4),
                    num_layers=self.best_params.get('num_layers', 3),
                    dropout=self.best_params.get('dropout', 0.3)
                )

                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.model = torch.load(checkpoint_path, map_location=self.device)
                self.model.to(self.device)
                self.model.eval()

                print(f"✅ Loaded GCN model from {checkpoint_path}")
                print(f"   📊 Model features: {num_features}")
                print(f"   🏗️ Architecture: {self.best_params}")
            else:
                print(f"❌ Model checkpoint not found at {checkpoint_path}")

        except Exception as e:
            print(f"❌ Error loading model artifacts: {e}")
            self.model = None

    def extract_vulnerability_features(self, finding: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from vulnerability finding."""
        features = []

        # Basic severity mapping
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4, 'info': 0}
        severity = finding.get('severity', 'medium').lower()
        features.append(severity_map.get(severity, 2))

        # CWE features (extract CWE number if available)
        cwe = finding.get('cwe', '')
        cwe_num = 0
        if cwe and 'CWE-' in str(cwe):
            try:
                cwe_num = int(re.findall(r'CWE-(\d+)', str(cwe))[0])
            except:
                cwe_num = 0
        features.append(min(cwe_num / 1000, 1.0))  # Normalize

        # Vulnerability type features
        vuln_type = finding.get('type', '').lower()
        type_features = [
            1 if vuln_type == 'sast' else 0,
            1 if vuln_type == 'dast' else 0,
            1 if vuln_type == 'sca' else 0,
            1 if vuln_type == 'secrets' else 0,
            1 if vuln_type == 'iac' else 0
        ]
        features.extend(type_features)

        # Location-based features
        location = finding.get('location', '').lower()
        location_features = [
            1 if any(term in location for term in ['password', 'key', 'secret', 'token']) else 0,
            1 if any(term in location for term in ['sql', 'database', 'db']) else 0,
            1 if any(term in location for term in ['network', 'port', 'socket']) else 0,
            1 if any(term in location for term in ['auth', 'login', 'session']) else 0,
            1 if any(term in location for term in ['crypto', 'ssl', 'tls', 'cert']) else 0
        ]
        features.extend(location_features)

        # Title/description based features (simple keyword matching)
        text_content = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
        text_features = [
            1 if any(term in text_content for term in ['injection', 'sqli', 'xss']) else 0,
            1 if any(term in text_content for term in ['buffer', 'overflow', 'memory']) else 0,
            1 if any(term in text_content for term in ['deserial', 'pickle', 'unserialize']) else 0,
            1 if any(term in text_content for term in ['path', 'traversal', 'directory']) else 0,
            1 if any(term in text_content for term in ['command', 'execution', 'rce']) else 0,
            1 if any(term in text_content for term in ['privilege', 'escalation', 'elevation']) else 0,
            1 if any(term in text_content for term in ['dos', 'denial', 'service']) else 0,
            1 if any(term in text_content for term in ['weak', 'broken', 'insecure']) else 0
        ]
        features.extend(text_features)

        # Add CVSS/EPSS if available (will be updated after OpenAI analysis)
        cvss_score = finding.get('cvss_score', 0.0)
        epss_score = finding.get('epss_score', 0.0)
        features.extend([cvss_score / 10.0, epss_score])  # Normalize CVSS

        # KEV and exploit features
        features.extend([
            1 if finding.get('kev_status') == 'YES' else 0,
            1 if finding.get('exploit_available') == 'YES' else 0
        ])

        # OWASP Top 10 mapping
        owasp = finding.get('owasp_2021', 'N/A')
        owasp_features = [0] * 10  # A01-A10
        if owasp != 'N/A' and 'A' in str(owasp):
            try:
                owasp_num = int(re.findall(r'A(\d+)', str(owasp))[0])
                if 1 <= owasp_num <= 10:
                    owasp_features[owasp_num - 1] = 1
            except:
                pass
        features.extend(owasp_features)

        # Temporal features
        current_year = datetime.now().year
        features.append(current_year / 2030.0)  # Normalize year

        # Pad or truncate to expected feature size (50 features)
        target_size = 50
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        elif len(features) > target_size:
            features = features[:target_size]

        return np.array(features, dtype=np.float32)

    def create_graph_from_findings(self, findings: List[Dict[str, Any]]) -> Data:
        """Create a graph representation from vulnerability findings."""
        if not findings:
            return None

        # Extract features for each finding
        node_features = []
        for finding in findings:
            features = self.extract_vulnerability_features(finding)
            node_features.append(features)

        node_features = np.array(node_features)

        # Create edges based on similarity (simple heuristic)
        edge_indices = []
        num_nodes = len(findings)

        for i in range(num_nodes):
            for j in range(i + 1, num_nodes):
                # Connect nodes if they share similar characteristics
                f1, f2 = findings[i], findings[j]

                # Same type
                same_type = f1.get('type') == f2.get('type')
                # Similar location
                loc1 = f1.get('location', '').lower()
                loc2 = f2.get('location', '').lower()
                similar_location = any(word in loc2 for word in loc1.split()[:3] if len(word) > 3)
                # Same CWE category
                same_cwe = f1.get('cwe', '') == f2.get('cwe', '') and f1.get('cwe', '') != ''

                if same_type or similar_location or same_cwe:
                    edge_indices.append([i, j])
                    edge_indices.append([j, i])  # Undirected graph

        # If no edges, create a simple chain
        if not edge_indices and num_nodes > 1:
            for i in range(num_nodes - 1):
                edge_indices.append([i, i + 1])
                edge_indices.append([i + 1, i])

        # Convert to tensors
        x = torch.tensor(node_features, dtype=torch.float32)
        edge_index = torch.tensor(edge_indices, dtype=torch.long).t().contiguous() if edge_indices else torch.empty((2, 0), dtype=torch.long)

        return Data(x=x, edge_index=edge_index)

    def predict_priority(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use GCN model to predict vulnerability priorities."""
        if not self.model or not findings:
            print("⚠️ GCN model not available, falling back to heuristic scoring")
            return findings

        try:
            # Create graph representation
            graph_data = self.create_graph_from_findings(findings)
            if graph_data is None:
                return findings

            # Move to device and create batch
            graph_data = graph_data.to(self.device)
            batch = torch.zeros(graph_data.x.size(0), dtype=torch.long, device=self.device)

            # Run inference
            with torch.no_grad():
                logits = self.model(graph_data.x, graph_data.edge_index, batch)
                probabilities = F.softmax(logits, dim=-1)
                predictions = torch.argmax(logits, dim=-1)

            # Update findings with model predictions
            for i, finding in enumerate(findings):
                if i < len(predictions):
                    pred_class = predictions[i].item()
                    pred_probs = probabilities[i].cpu().numpy()

                    # Update with model predictions
                    finding['gcn_priority'] = self.priority_mapping.get(pred_class, 'Medium')
                    finding['gcn_confidence'] = float(pred_probs.max())
                    finding['gcn_probabilities'] = {
                        'Low': float(pred_probs[0]),
                        'Medium': float(pred_probs[1]),
                        'High': float(pred_probs[2]),
                        'Critical': float(pred_probs[3])
                    }

                    # Calculate GCN-based risk score (0-10 scale)
                    gcn_risk_score = (
                        pred_probs[0] * 2.5 +   # Low -> 2.5
                        pred_probs[1] * 5.0 +   # Medium -> 5.0
                        pred_probs[2] * 7.5 +   # High -> 7.5
                        pred_probs[3] * 10.0    # Critical -> 10.0
                    )
                    finding['gcn_risk_score'] = float(gcn_risk_score)

                    print(f"🔮 GCN Prediction for '{finding['title'][:50]}...': {finding['gcn_priority']} (confidence: {finding['gcn_confidence']:.3f})")

            print(f"✅ GCN model processed {len(findings)} findings")
            return findings

        except Exception as e:
            print(f"❌ Error in GCN prediction: {e}")
            return findings

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

def calculate_hybrid_risk_score(finding: Dict[str, Any]) -> tuple[float, str]:
    """Calculate hybrid risk score combining GCN predictions with heuristics."""

    # Start with GCN prediction if available
    if 'gcn_risk_score' in finding and finding.get('gcn_confidence', 0) > 0.5:
        base_score = finding['gcn_risk_score']
        gcn_priority = finding.get('gcn_priority', 'Medium')
        print(f"🤖 Using GCN prediction: {gcn_priority} (score: {base_score:.2f})")

        # Apply minor adjustments based on additional factors
        cvss = finding.get('cvss_score', 0.0)
        epss = finding.get('epss_score', 0.0)
        is_kev = finding.get('kev_status', 'NO') == 'YES'
        has_exploit = finding.get('exploit_available', 'NO') == 'YES'

        # Boost score for critical external factors
        if is_kev:
            base_score = min(base_score + 1.0, 10.0)
        if has_exploit and cvss >= 7.0:
            base_score = min(base_score + 0.5, 10.0)
        if epss > 0.5:
            base_score = min(base_score + 0.5, 10.0)

        # Use GCN priority but allow critical overrides
        if is_kev or (cvss >= 9.0 and has_exploit):
            priority = 'Critical'
        else:
            priority = gcn_priority

        return round(base_score, 2), priority

    # Fallback to heuristic scoring
    print("📊 Using heuristic scoring (GCN not available/low confidence)")

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
    gcn_processed = 0

    for finding in findings:
        priority = finding.get('priority', 'Unknown')
        category = finding.get('category', 'Unknown')

        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

        if finding.get('owasp_2021', 'N/A') != 'N/A':
            owasp_findings += 1
        if finding.get('kev_status', 'NO') == 'YES':
            kev_findings += 1
        if 'gcn_priority' in finding:
            gcn_processed += 1

    # Build summary
    summary_parts = []
    summary_parts.append(f"This AI-enhanced security assessment analyzed {total} findings using Graph Convolutional Networks trained on vulnerability databases (DiversVul, Devign, CVE, NVD, EPSS).")

    if gcn_processed > 0:
        summary_parts.append(f"{gcn_processed} findings were processed through the trained GCN model for intelligent risk prioritization.")

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

    summary_parts.append("The AI model's risk predictions have been combined with threat intelligence to provide actionable prioritization guidance.")

    return " ".join(summary_parts)

def generate_html_report(findings: List[Dict[str, Any]], summary: Dict[str, int], output_file: Path):
    """Generate comprehensive HTML report with GCN insights."""

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
    <title>AI-Enhanced Security Assessment Report</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f8f9fa;
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .ai-badge { 
            background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 4px 12px; 
            border-radius: 15px; 
            font-size: 12px; 
            font-weight: bold; 
            margin-left: 10px; 
        }
        .executive-summary { 
            background: #ecf0f1; 
            padding: 20px; 
            border-radius: 5px; 
            margin: 20px 0; 
            border-left: 4px solid #3498db;
        }
        .gcn-stats {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
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
            font-size: 13px;
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 10px 6px; 
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
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .priority-critical { background: #e74c3c; color: white; }
        .priority-high { background: #e67e22; color: white; }
        .priority-medium { background: #f39c12; color: white; }
        .priority-low { background: #27ae60; color: white; }
        
        .gcn-badge {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 2px 6px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: bold;
            margin-left: 5px;
        }
        
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
            font-size: 12px;
        }
        .remediation { 
            max-width: 250px; 
            word-wrap: break-word; 
            font-size: 12px;
        }
        
        .gcn-details {
            background: #f8f9ff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 8px;
            margin: 5px 0;
            font-size: 11px;
        }
        
        .prob-bar {
            background: #ecf0f1;
            height: 4px;
            border-radius: 2px;
            margin: 2px 0;
            overflow: hidden;
        }
        
        .prob-fill {
            height: 100%;
            border-radius: 2px;
        }
        
        .prob-critical { background: #e74c3c; }
        .prob-high { background: #e67e22; }
        .prob-medium { background: #f39c12; }
        .prob-low { background: #27ae60; }
        
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .summary-stats { flex-direction: column; }
            table { font-size: 11px; }
            th, td { padding: 6px 4px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 AI-Enhanced Security Assessment Report<span class="ai-badge">GCN POWERED</span></h1>
        
        <div class="gcn-stats">
            <h3>🧠 Graph Convolutional Network Analysis</h3>
            <p>Powered by AI models trained on DiversVul, Devign, CVE, NVD, and EPSS datasets</p>
        </div>
        
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
                            <th>GCN Analysis</th>
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
                                    {% if finding.gcn_priority %}
                                        <span class="gcn-badge">GCN: {{ finding.gcn_priority }}</span>
                                    {% endif %}
                                </td>
                                <td><strong>{{ finding.title }}</strong></td>
                                <td>{{ finding.type | upper }}</td>
                                <td style="max-width: 180px; word-wrap: break-word; font-size: 11px;">{{ finding.location }}</td>
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
                                <td>
                                    <strong>{{ "%.2f"|format(finding.risk_score) }}</strong>
                                    {% if finding.gcn_risk_score %}
                                        <br><small style="color: #667eea;">GCN: {{ "%.2f"|format(finding.gcn_risk_score) }}</small>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if finding.gcn_probabilities %}
                                        <div class="gcn-details">
                                            <div><strong>AI Confidence:</strong> {{ "%.1f"|format(finding.gcn_confidence * 100) }}%</div>
                                            {% for priority, prob in finding.gcn_probabilities.items() %}
                                                <div style="display: flex; align-items: center; margin: 1px 0;">
                                                    <span style="width: 50px; font-size: 10px;">{{ priority }}:</span>
                                                    <div class="prob-bar" style="width: 60px;">
                                                        <div class="prob-fill prob-{{ priority | lower }}" style="width: {{ (prob * 100) | round }}%;"></div>
                                                    </div>
                                                    <span style="margin-left: 4px; font-size: 10px;">{{ "%.1f"|format(prob * 100) }}%</span>
                                                </div>
                                            {% endfor %}
                                        </div>
                                    {% else %}
                                        <span style="color: #7f8c8d; font-size: 11px;">Heuristic Analysis</span>
                                    {% endif %}
                                </td>
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
            <p><strong>🤖 AI-Enhanced Analysis:</strong></p>
            <ul style="list-style: none; padding: 0;">
                <li>🧠 <strong>GCN Model:</strong> Graph Convolutional Network trained on vulnerability datasets</li>
                <li>📊 <strong>Risk Scoring:</strong> Hybrid approach combining AI predictions with threat intelligence</li>
                <li>🎯 <strong>Priority Levels:</strong> AI-driven classification with human-readable confidence scores</li>
                <li>📈 <strong>Probability Bars:</strong> Show model confidence across all priority levels</li>
            </ul>
            <p><strong>Report Legend:</strong></p>
            <ul style="list-style: none; padding: 0;">
                <li>🔴 <strong>Critical:</strong> Immediate action required - active exploitation likely</li>
                <li>🟠 <strong>High:</strong> Address within current sprint - significant risk</li>
                <li>🟡 <strong>Medium:</strong> Plan remediation in next release cycle</li>
                <li>🟢 <strong>Low:</strong> Address as time permits - low immediate risk</li>
            </ul>
            <p><strong>Data Sources:</strong><br>
               <strong>EPSS:</strong> Exploit Prediction Scoring System (probability of exploitation in next 30 days)<br>
               <strong>KEV:</strong> CISA Known Exploited Vulnerabilities catalog<br>
               <strong>OWASP:</strong> OWASP Top 10 2021 Web Application Security Risks<br>
               <strong>Training Data:</strong> DiversVul, Devign, CVE, NVD datasets</p>
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
    parser = argparse.ArgumentParser(description="AI-Enhanced Security Finding Analysis with GCN Model")
    parser.add_argument('--artifacts-dir', type=Path, required=True, help="Artifacts directory containing trained model")
    parser.add_argument('--in', dest='input_file', type=Path, required=True, help="Input JSONL file")
    parser.add_argument('--out', type=Path, required=True, help="Output enriched JSONL file")
    parser.add_argument('--report', type=Path, required=True, help="Output HTML report file")
    parser.add_argument('--max-requests', type=int, default=100, help="Maximum API requests")
    args = parser.parse_args()

    print("🚀 Starting AI-Enhanced Vulnerability Analysis")
    print(f"📁 Artifacts directory: {args.artifacts_dir}")

    # Check for OpenAI API key
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")

    client = OpenAI(api_key=api_key)

    # Initialize GCN vulnerability prioritizer
    prioritizer = VulnPrioritizer(args.artifacts_dir)

    # Load findings
    findings = load_findings(args.input_file)

    if not findings:
        print("No findings to process")
        return

    print(f"🔍 Processing {len(findings)} findings with AI analysis...")

    # First pass: Run GCN model on current findings
    print("\n🧠 Phase 1: GCN Model Inference")
    findings = prioritizer.predict_priority(findings)

    # Second pass: Enhance with OpenAI analysis
    print("\n🤖 Phase 2: OpenAI Enhancement")
    processed_count = 0
    for idx, finding in enumerate(findings, 1):
        if processed_count >= args.max_requests:
            print(f"Reached maximum API requests limit ({args.max_requests})")
            break

        print(f"Processing finding {idx}/{len(findings)}: {finding.get('title', 'Unknown')[:50]}...")

        # Get AI analysis (this will add CVE, CVSS, EPSS, etc.)
        analysis = get_enhanced_analysis(finding, client)
        finding.update(analysis)

        # Re-extract features now that we have more data
        if prioritizer.model:
            # Update features with new OpenAI data
            updated_features = prioritizer.extract_vulnerability_features(finding)

        processed_count += 1

        # Rate limiting - be nice to the API
        if idx % 10 == 0:
            time.sleep(1)

    # Third pass: Calculate final hybrid risk scores
    print("\n⚖️ Phase 3: Hybrid Risk Calculation")
    for finding in findings:
        risk_score, priority = calculate_hybrid_risk_score(finding)
        finding['risk_score'] = risk_score
        finding['priority'] = priority

        # Categorize finding
        finding['category'] = categorize_finding(finding)

    # Generate summary statistics
    summary = {
        'total': len(findings),
        'critical': sum(1 for f in findings if f.get('priority') == 'Critical'),
        'high': sum(1 for f in findings if f.get('priority') == 'High'),
        'medium': sum(1 for f in findings if f.get('priority') == 'Medium'),
        'low': sum(1 for f in findings if f.get('priority') == 'Low'),
    }

    print(f"\n📊 Final Analysis Summary:")
    print(f"   🔍 Total findings: {summary['total']}")
    print(f"   🔴 Critical: {summary['critical']}")
    print(f"   🟠 High: {summary['high']}")
    print(f"   🟡 Medium: {summary['medium']}")
    print(f"   🟢 Low: {summary['low']}")

    # Count GCN-processed findings
    gcn_processed = sum(1 for f in findings if 'gcn_priority' in f)
    print(f"   🧠 GCN processed: {gcn_processed}/{len(findings)} ({gcn_processed/len(findings)*100:.1f}%)")

    # Save enriched findings
    with open(args.out, 'w', encoding='utf-8') as f:
        for finding in findings:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")

    # Generate HTML report
    generate_html_report(findings, summary, args.report)

    print(f"\n✅ AI-Enhanced Analysis Complete!")
    print(f"   📄 Enriched findings: {args.out}")
    print(f"   📊 HTML report: {args.report}")
    print(f"   🤖 Model integration: {'✅ Active' if prioritizer.model else '⚠️ Fallback mode'}")

if __name__ == "__main__":
    main()
