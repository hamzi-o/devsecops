import argparse
import json
import pickle
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
import numpy as np
import pandas as pd
from pathlib import Path
import html

class GCN(torch.nn.Module):
    def __init__(self, in_dim, hidden_dim, dropout_rate):
        super().__init__()
        self.conv1 = GCNConv(in_dim, hidden_dim)
        self.bn1 = torch.nn.BatchNorm1d(hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim // 2)
        self.bn2 = torch.nn.BatchNorm1d(hidden_dim // 2)
        self.fc = torch.nn.Linear(hidden_dim // 2, 1)
        self.dropout = torch.nn.Dropout(dropout_rate)

    def forward(self, x, edge_index, edge_attr=None):
        x = F.relu(self.bn1(self.conv1(x, edge_index, edge_attr)))
        x = self.dropout(x)
        x = F.relu(self.bn2(self.conv2(x, edge_index, edge_attr)))
        x = self.dropout(x)
        x = self.fc(x)
        return x

def load_findings(findings_file):
    findings = []
    with open(findings_file, 'r') as f:
        for line in f:
            finding = json.loads(line.strip())
            findings.append(finding)
    return findings

def create_graph_data(findings, scaler):
    x_list, edge_list, edge_attr_list, locations = [], [], [], []
    node_mapping = {}
    
    for idx, finding in enumerate(findings):
        node_id = f"finding:{idx}"
        node_mapping[node_id] = idx
        
        # Extract features
        cvss = float(finding.get('cvss_score', 0.0))
        epss = float(finding.get('epss_score', 0.0))
        is_kev = int(finding.get('is_kev', 0))
        code_emb = np.zeros(768, dtype=np.float32)  # Placeholder for CodeBERT
        node_type = [1, 0] if finding.get('type') == 'vuln' else [0, 1]
        
        # Extract location for report
        location = finding.get('location', 'Unknown')
        locations.append(location)
        
        # Combine features
        feat = np.concatenate([node_type, [cvss, epss, is_kev], code_emb]).astype(np.float32)
        feat = np.nan_to_num(feat, nan=0.0, posinf=0.0, neginf=0.0)
        x_list.append(feat)
        
        # Add synthetic edges (e.g., connect findings with same package)
        pkg = finding.get('package', None)
        if pkg:
            for j, other in enumerate(findings):
                if j != idx and other.get('package') == pkg:
                    edge_list.append([idx, j])
                    edge_attr_list.append([max(cvss / 10.0, epss)])
    
    # Normalize features
    x_array = np.array(x_list, dtype=np.float32)
    if x_array.shape[0] > 0:
        x_array[:, 2:4] = scaler.transform(x_array[:, 2:4])
    
    # Create PyG Data
    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous() if edge_list else torch.empty((2, 0), dtype=torch.long)
    edge_attr = torch.tensor(edge_attr_list, dtype=torch.float32) if edge_attr_list else torch.empty((0,), dtype=torch.float32)
    x = torch.tensor(x_array, dtype=torch.float32)
    return Data(x=x, edge_index=edge_index, edge_attr=edge_attr), locations

def generate_html_report(findings, scores, locations, output_file):
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Report</title>
        <style>
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid black; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Security Report</h1>
        <table>
            <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Location</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th>Risk Score</th>
            </tr>
    """
    for idx, (finding, score, loc) in enumerate(zip(findings, scores, locations)):
        html_content += f"""
            <tr>
                <td>{html.escape(str(finding.get('id', idx)))}</td>
                <td>{html.escape(str(finding.get('type', 'Unknown')))}</td>
                <td>{html.escape(str(loc))}</td>
                <td>{finding.get('cvss_score', 0.0):.1f}</td>
                <td>{finding.get('epss_score', 0.0):.4f}</td>
                <td>{'Yes' if finding.get('is_kev', 0) else 'No'}</td>
                <td>{score:.4f}</td>
            </tr>
        """
    html_content += """
        </table>
    </body>
    </html>
    """
    with open(output_file, 'w') as f:
        f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description="Run inference on security findings")
    parser.add_argument('--artifacts-dir', required=True, help="Directory containing model artifacts")
    parser.add_argument('--in', required=True, dest='input_file', help="Input findings file (JSONL)")
    parser.add_argument('--out', required=True, dest='output_file', help="Output enriched findings file (JSONL)")
    parser.add_argument('--report', required=True, help="Output HTML report file")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    artifacts_dir = Path(args.artifacts_dir)
    
    # Load artifacts
    scaler = pickle.load(open(artifacts_dir / "scaler.pkl", "rb"))
    best_params = pickle.load(open(artifacts_dir / "best_params.pkl", "rb"))
    model = GCN(in_dim=773, hidden_dim=best_params['hidden_dim'], dropout_rate=best_params['dropout_rate']).to(device)
    model.load_state_dict(torch.load(artifacts_dir / "vuln_prioritizer_checkpoint.pt", map_location=device))
    model.eval()

    # Load findings
    findings = load_findings(args.input_file)
    data, locations = create_graph_data(findings, scaler)
    data = data.to(device)

    # Run inference
    with torch.no_grad():
        scores = torch.sigmoid(model(data.x, data.edge_index, data.edge_attr)).cpu().numpy().flatten()

    # Enrich findings
    enriched = []
    for finding, score, loc in zip(findings, scores, locations):
        finding['risk_score'] = float(score)
        finding['location'] = loc
        enriched.append(finding)
    
    # Save enriched findings
    with open(args.output_file, 'w') as f:
        for finding in enriched:
            f.write(json.dumps(finding) + '\n')
    
    # Generate HTML report
    generate_html_report(findings, scores, locations, args.report)

if __name__ == "__main__":
    main()
