import argparse
import json
import logging
import pathlib
import os
from typing import Dict, List, Any
import torch
import torch.nn as nn
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import MinMaxScaler
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import yaml
from openai import OpenAI
import joblib
from lightgbm import LGBMClassifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define the GNN model architecture to match checkpoint
class VulnPrioritizer(nn.Module):
    def __init__(self, input_dim=773, hidden_dim1=512, hidden_dim2=256, output_dim=1):
        super(VulnPrioritizer, self).__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim1)
        self.bn1 = nn.BatchNorm1d(hidden_dim1)
        self.conv2 = GCNConv(hidden_dim1, hidden_dim2)
        self.bn2 = nn.BatchNorm1d(hidden_dim2)
        self.fc = nn.Linear(hidden_dim2, output_dim)
        self.relu = nn.ReLU()

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = self.relu(x)
        x = self.fc(x)
        return x

def load_findings(findings_path: pathlib.Path) -> List[Dict[str, Any]]:
    """Load findings from a JSONL file."""
    findings = []
    try:
        with open(findings_path, 'r') as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))
        logger.info(f"Loaded {len(findings)} findings from {findings_path}")
    except Exception as e:
        logger.error(f"Error loading findings: {e}")
        raise
    return findings

def preprocess_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Preprocess findings to extract relevant features."""
    processed = []
    for finding in findings:
        try:
            processed_finding = {
                'id': finding.get('id', ''),
                'title': finding.get('title', ''),
                'description': finding.get('description', ''),
                'severity': finding.get('severity', 'Unknown'),
                'cve': finding.get('cve', ''),
                'cvss': float(finding.get('cvss', 0.0)),
                'epss': float(finding.get('epss', 0.0)),
                'kev': finding.get('kev', False),
                'owasp': finding.get('owasp', ''),
                'category': finding.get('category', 'Unknown'),
                'source': finding.get('source', 'Unknown'),
                'file': finding.get('file', ''),
                'line': finding.get('line', 0)
            }
            processed.append(processed_finding)
        except Exception as e:
            logger.warning(f"Error processing finding {finding.get('id', 'unknown')}: {e}")
            continue
    return processed

def generate_embeddings(findings: List[Dict[str, Any]], model: SentenceTransformer) -> np.ndarray:
    """Generate embeddings for findings using a sentence transformer."""
    texts = [f"{f['title']} {f['description']}" for f in findings]
    try:
        embeddings = model.encode(texts, convert_to_numpy=True)
        logger.info(f"Generated embeddings for {len(embeddings)} findings")
        return embeddings
    except Exception as e:
        logger.error(f"Error generating embeddings: {e}")
        raise

def build_graph(embeddings: np.ndarray, findings: List[Dict[str, Any]]) -> Data:
    """Build a graph from embeddings and findings."""
    try:
        num_nodes = len(embeddings)
        edge_index = torch.tensor([[], []], dtype=torch.long)  # Placeholder: Add edge logic if needed
        x = torch.tensor(embeddings, dtype=torch.float)
        y = torch.tensor([0] * num_nodes, dtype=torch.long)  # Placeholder labels
        data = Data(x=x, edge_index=edge_index, y=y)
        logger.info(f"Built graph with {num_nodes} nodes")
        return data
    except Exception as e:
        logger.error(f"Error building graph: {e}")
        raise

def prioritize_vulnerabilities(data: Data, model: nn.Module, scaler: MinMaxScaler) -> np.ndarray:
    """Prioritize vulnerabilities using the trained model."""
    try:
        model.eval()
        with torch.no_grad():
            out = model(data.x, edge_index=data.edge_index)
            scores = out.cpu().numpy().flatten()
            scores = scaler.transform(scores.reshape(-1, 1)).flatten()
        logger.info(f"Generated prioritization scores for {len(scores)} findings")
        return scores
    except Exception as e:
        logger.error(f"Error prioritizing vulnerabilities: {e}")
        raise

def enrich_findings(findings: List[Dict[str, Any]], scores: np.ndarray, client: OpenAI) -> List[Dict[str, Any]]:
    """Enrich findings with AI-generated insights and risk scores."""
    enriched = []
    for i, finding in enumerate(findings):
        try:
            prompt = f"""
            Analyze the following vulnerability:
            Title: {finding['title']}
            Description: {finding['description']}
            Severity: {finding['severity']}
            CVE: {finding['cve']}
            CVSS: {finding['cvss']}
            EPSS: {finding['epss']}
            KEV: {finding['kev']}
            OWASP: {finding['owasp']}
            Provide a brief explanation of the risk and recommended mitigation.
            """
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200
            )
            explanation = response.choices[0].message.content.strip()
            enriched_finding = finding.copy()
            enriched_finding['risk_score'] = float(scores[i])
            enriched_finding['ai_explanation'] = explanation
            enriched_finding['priority'] = 'High' if scores[i] >= 0.7 else 'Medium' if scores[i] >= 0.3 else 'Low'
            enriched.append(enriched_finding)
        except Exception as e:
            logger.warning(f"Error enriching finding {finding.get('id', 'unknown')}: {e}")
            enriched_finding = finding.copy()
            enriched_finding['risk_score'] = float(scores[i])
            enriched_finding['ai_explanation'] = "Failed to generate explanation."
            enriched_finding['priority'] = 'Medium'
            enriched.append(enriched_finding)
    return enriched

def generate_html_report(findings: List[Dict[str, Any]], output_path: pathlib.Path):
    """Generate an HTML report using a Jinja2 template."""
    try:
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report.html')
        
        # Categorize findings
        categories = {'App': [], 'Packages': [], 'Infrastructure': [], 'Dependencies': []}
        for finding in findings:
            category = finding.get('category', 'Dependencies')
            if category in categories:
                categories[category].append(finding)
            else:
                categories['Dependencies'].append(finding)
        
        # Calculate summary
        total_findings = len(findings)
        high_risk = sum(1 for f in findings if f['priority'] == 'High')
        medium_risk = sum(1 for f in findings if f['priority'] == 'Medium')
        low_risk = sum(1 for f in findings if f['priority'] == 'Low')
        
        # Render report
        html_content = template.render(
            categories=categories,
            summary={
                'total': total_findings,
                'high': high_risk,
                'medium': medium_risk,
                'low': low_risk
            }
        )
        output_path.write_text(html_content)
        logger.info(f"Generated HTML report at {output_path}")
    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Run AI-based vulnerability inference.")
    parser.add_argument('--artifacts-dir', type=pathlib.Path, required=True, help="Directory containing model artifacts")
    parser.add_argument('--in', type=pathlib.Path, dest='input', required=True, help="Input findings JSONL file")
    parser.add_argument('--out', type=pathlib.Path, required=True, help="Output enriched findings JSONL file")
    parser.add_argument('--report', type=pathlib.Path, required=True, help="Output HTML report file")
    args = parser.parse_args()

    # Load OpenAI API key
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.error("OPENAI_API_KEY environment variable not set")
        raise ValueError("OPENAI_API_KEY not set")

    # Initialize models and clients
    client = OpenAI(api_key=api_key)
    try:
        # Try loading SentenceTransformer from pre-cached directory
        sentence_model = SentenceTransformer(args.artifacts_dir / 'all-MiniLM-L6-v2')
    except Exception as e:
        logger.warning(f"Failed to load SentenceTransformer from {args.artifacts_dir / 'all-MiniLM-L6-v2'}: {e}. Falling back to default.")
        try:
            sentence_model = SentenceTransformer('all-MiniLM-L6-v2', local_files_only=True)
        except Exception as e:
            logger.warning(f"Failed to load SentenceTransformer from cache: {e}. Attempting to download.")
            sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
    model = VulnPrioritizer(input_dim=773)
    state_dict = torch.load(args.artifacts_dir / "vuln_prioritizer_checkpoint.pt", map_location=torch.device('cpu'), weights_only=True)
    model.load_state_dict(state_dict)
    scaler = joblib.load(args.artifacts_dir / "scaler.pkl")

    # Process findings
    findings = load_findings(args.input)
    processed_findings = preprocess_findings(findings)
    embeddings = generate_embeddings(processed_findings, sentence_model)
    graph_data = build_graph(embeddings, processed_findings)
    scores = prioritize_vulnerabilities(graph_data, model, scaler)
    enriched_findings = enrich_findings(processed_findings, scores, client)

    # Save enriched findings
    try:
        with open(args.out, 'w') as f:
            for finding in enriched_findings:
                f.write(json.dumps(finding) + '\n')
        logger.info(f"Saved enriched findings to {args.out}")
    except Exception as e:
        logger.error(f"Error saving enriched findings: {e}")
        raise

    # Generate HTML report
    generate_html_report(enriched_findings, args.report)

if __name__ == "__main__":
    main()
