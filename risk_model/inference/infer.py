from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
import networkx as nx
import numpy as np
from torch_geometric.utils import from_networkx
from torch_geometric.nn import SAGEConv
import os
import requests
import argparse
import jinja2
import json

app = FastAPI(title="Vulnerability Prioritization API")

class GraphRequest(BaseModel):
    graph_json: dict

class VGNN(torch.nn.Module):
    def __init__(self, in_channels, hidden=128):
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden)
        self.conv2 = SAGEConv(hidden, hidden)
        self.lin = torch.nn.Linear(hidden, 1)

    def forward(self, x, edge_index):
        x = torch.relu(self.conv1(x, edge_index))
        x = torch.relu(self.conv2(x, edge_index))
        return self.lin(x).squeeze(-1)

# Load model
ckpt = torch.load("artifacts/vuln_prioritizer_checkpoint.pt", map_location='cpu')
model = VGNN(in_channels=len(ckpt['type_to_idx']) + 5 + 768)
model.load_state_dict(ckpt['model_state_dict'])
model.eval()

@app.post("/rank")
def rank_graph(req: GraphRequest):
    try:
        G = nx.node_link_graph(req.graph_json)
        data = from_networkx(G, group_node_attrs=['feat_vec'])
        data.x = torch.tensor([n['feat_vec'] for _, n in G.nodes(data=True)]).float()
        with torch.no_grad():
            scores = torch.sigmoid(model(data.x, data.edge_index)).numpy()
        return {"node_ids": ckpt['node_id_map'], "scores": scores.tolist()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def to_priority(score):
    return "P1" if score >= 0.75 else ("P2" if score >= 0.55 else ("P3" if score >= 0.35 else "P4"))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", required=True)
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--openai-api-key", default=os.getenv("OPENAI_API_KEY"))
    ap.add_argument("--openai-model", default="gpt-4o-mini")
    a = ap.parse_args()

    # Build graph from findings
    G = nx.MultiDiGraph()
    findings = [json.loads(l) for l in open(a.inp)]
    for i, f in enumerate(findings):
        vuln_node = f"vuln:{f.get('cve', f'tmp_{i}')}"
        G.add_node(vuln_node, node_type='vuln', label=1, cvss=0.0, epss=0.0, is_kev=0, reachable=0, hit_count=0, code_emb=np.zeros(768))
        if 'cve' in f:
            r = requests.get(f"https://api.first.org/data/v1/epss?cve={f['cve']}", timeout=10)
            G.nodes[vuln_node]['epss'] = float(r.json()['data'][0]['epss']) if r.json().get('data') else 0.0
            G.nodes[vuln_node]['is_kev'] = 1 if f['cve'] in requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json().get('vulnerabilities', []) else 0

    # Add SBOM and runtime data
    sbom = json.load(open("sbom.json")) if os.path.exists("sbom.json") else {'artifacts': []}
    for pkg in sbom.get('artifacts', []):
        pkg_node = f"pkg:{pkg.get('name')}:{pkg.get('version')}"
        G.add_node(pkg_node, node_type='package', name=pkg.get('name'), version=pkg.get('version'))
        G.add_edge(vuln_node, pkg_node, edge_type='affects_package')

    # Convert to PyG
    types = list({d['node_type'] for _, d in G.nodes(data=True)})
    type_to_idx = {t: i for i, t in enumerate(types)}
    for n, d in G.nodes(data=True):
        oh = [0] * len(types); oh[type_to_idx[d['node_type']]] = 1
        feat = oh + [d.get('cvss', 0.0), d.get('epss', 0.0), d.get('is_kev', 0), d.get('reachable', 0), d.get('hit_count', 0)]
        feat += d['code_emb'].tolist()
        G.nodes[n]['feat_vec'] = np.array(feat, dtype=np.float32)
        G.nodes[n]['y'] = d.get('label', 0)

    data = from_networkx(G, group_node_attrs=['feat_vec', 'y'])
    data.x = torch.tensor([n['feat_vec'] for _, n in G.nodes(data=True)]).float()
    data.y = torch.tensor([n['y'] for _, n in G.nodes(data=True)]).long()

    # Inference
    with torch.no_grad():
        scores = torch.sigmoid(model(data.x, data.edge_index)).numpy()
    node_ids = list(G.nodes())
    enriched = []
    for f, node, score in zip(findings, node_ids, scores):
        f["risk_score"] = float(score)
        f["priority"] = to_priority(float(score))
        enriched.append(f)

    with open(a.out, "w") as f:
        for e in enriched: f.write(json.dumps(e) + "\n")

    # Generate LLM report (optional)
    llm_summary = "(LLM disabled)"
    if a.openai_api_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=a.openai_api_key)
            top = sorted(enriched, key=lambda x: x["risk_score"], reverse=True)[:15]
            prompt = "Summarize and prioritize these findings and propose concrete remediation steps:\n" + json.dumps(top, indent=2)
            resp = client.chat.completions.create(model=a.openai_model, messages=[{"role": "user", "content": prompt}], temperature=0.2)
            llm_summary = resp.choices[0].message.content
        except Exception as e:
            llm_summary = f"(LLM summary unavailable: {str(e)}. Check API key or network.)"

    tpl = jinja2.Template(open("reporting/template.html").read())
    html = tpl.render(findings=enriched, summary=llm_summary)
    open(a.report, "w").write(html)
    print("Report written:", a.report)
