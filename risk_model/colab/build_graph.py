import networkx as nx
from torch_geometric.utils import from_networkx
from torch_geometric.nn import SAGEConv
import torch
import torch.nn.functional as F
import numpy as np

SAVE_DIR = "/content/drive/MyDrive/processed_datasets"
G = nx.MultiDiGraph()

# Load datasets with embeddings
df_diversevul = pd.read_pickle(os.path.join(SAVE_DIR, "df_diversevul_with_emb.pkl"))
df_devign    = pd.read_pickle(os.path.join(SAVE_DIR, "df_devign_with_emb.pkl"))
df_nvd       = pd.read_pickle(os.path.join(SAVE_DIR, "df_nvd.pkl"))
df_epss      = pd.read_pickle(os.path.join(SAVE_DIR, "df_epss.pkl"))
df_kev       = pd.read_pickle(os.path.join(SAVE_DIR, "df_kev.pkl"))
kev_cves = set(df_kev['cve'].tolist())

# -------------------
# 3.1 Add vulnerability nodes
# -------------------
def add_vuln_nodes(df, code_column="raw_code"):
    for _, r in df.iterrows():
        cve_id = r.get('cve', f'tmp_{_}')
        vuln_node = f"vuln:{cve_id}:{_}"
        code_emb = r[code_column] if code_column in r and isinstance(r[code_column], np.ndarray) else np.zeros(768)
        epss = float(r.get('epss', 0.0)) if 'epss' in r else 0.0
        cvss3 = float(r.get('cvss3_baseScore', 0.0)) if 'cvss3_baseScore' in r else 0.0
        cvss2 = float(r.get('cvss2_baseScore', 0.0)) if 'cvss2_baseScore' in r else 0.0
        is_kev = 1 if cve_id in kev_cves else 0
        label = int(r.get('label', 0))
        G.add_node(vuln_node, node_type='vuln', label=label,
                   cvss3=cvss3, cvss2=cvss2, epss=epss,
                   is_kev=is_kev, code_emb=code_emb, reachable=np.random.randint(0,2),
                   hit_count=np.random.randint(0,5))

# Add nodes for DiverseVul and Devign
add_vuln_nodes(df_diversevul)
add_vuln_nodes(df_devign)

# -------------------
# 3.2 Add SBOM nodes
# -------------------
sbom = json.load(open(os.path.join(SAVE_DIR, "sbom.json")))
for pkg in sbom.get('artifacts', []):
    pkg_node = f"pkg:{pkg.get('name')}:{pkg.get('version')}"
    G.add_node(pkg_node, node_type='package', name=pkg.get('name'), version=pkg.get('version'))
    # For demo, connect all vulnerabilities to all packages
    for vuln_node in [n for n,d in G.nodes(data=True) if d['node_type']=='vuln']:
        G.add_edge(vuln_node, pkg_node, edge_type='affects_package')
