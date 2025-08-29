types = list({d['node_type'] for _, d in G.nodes(data=True)})
type_to_idx = {t:i for i,t in enumerate(types)}

for n,d in G.nodes(data=True):
    oh = [0]*len(types)
    oh[type_to_idx[d['node_type']]] = 1
    feat = oh + [d.get('cvss3',0.0), d.get('cvss2',0.0), d.get('epss',0.0),
                 d.get('is_kev',0), d.get('reachable',0), d.get('hit_count',0)]
    if 'code_emb' in d:
        feat += d['code_emb'].flatten().tolist()
    G.nodes[n]['feat_vec'] = np.array(feat, dtype=np.float32)
    G.nodes[n]['y'] = int(d['label']) if d['node_type']=='vuln' else 0

data = from_networkx(G, group_node_attrs=['feat_vec','y'])
data.x = torch.tensor([n['feat_vec'] for _,n in G.nodes(data=True)]).float()
data.y = torch.tensor([n['y'] for _,n in G.nodes(data=True)]).long()

# -------------------
# 3.4 Define GraphSAGE Model
# -------------------
class VGNN(torch.nn.Module):
    def __init__(self, in_channels, hidden=128):
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden)
        self.conv2 = SAGEConv(hidden, hidden)
        self.lin = torch.nn.Linear(hidden, 1)
    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.relu(self.conv2(x, edge_index))
        return self.lin(x).squeeze(-1)

model = VGNN(data.x.shape[1]).to('cuda' if torch.cuda.is_available() else 'cpu')
opt = torch.optim.Adam(model.parameters(), lr=1e-3)
loss_fn = torch.nn.BCEWithLogitsLoss()

from sklearn.metrics import accuracy_score, roc_auc_score, f1_score, precision_score

# -------------------
# 3.5 Train-test split and training loop (demo)
# -------------------
is_vuln = [d['node_type']=='vuln' for _, d in G.nodes(data=True)]
vuln_idx = [i for i,v in enumerate(is_vuln) if v]
perm = torch.randperm(len(vuln_idx))
train_idx = torch.tensor(vuln_idx)[perm[:int(0.8*len(perm))]]
test_idx  = torch.tensor(vuln_idx)[perm[int(0.8*len(perm)):]]


device = 'cuda' if torch.cuda.is_available() else 'cpu'
data.x = data.x.to(device)
data.edge_index = data.edge_index.to(device)
data.y = data.y.to(device)
model = model.to(device)

for epoch in range(1, 11):  # demo: 10 epochs
    model.train()
    opt.zero_grad()
    logits = model(data.x, data.edge_index)
    loss = loss_fn(logits[train_idx], data.y[train_idx].float())
    loss.backward()
    opt.step()
    
    if epoch % 2 == 0:
        model.eval()
        with torch.no_grad():
            train_preds = torch.sigmoid(model(data.x, data.edge_index))[train_idx].cpu().numpy()
            test_preds  = torch.sigmoid(model(data.x, data.edge_index))[test_idx].cpu().numpy()
            train_labels = data.y[train_idx].cpu().numpy()
            test_labels  = data.y[test_idx].cpu().numpy()

        # Binarize with 0.5 threshold
        train_pred_bin = (train_preds >= 0.5).astype(int)
        test_pred_bin  = (test_preds >= 0.5).astype(int)

        # Metrics
        train_acc = accuracy_score(train_labels, train_pred_bin)
        test_acc  = accuracy_score(test_labels, test_pred_bin)
        train_f1 = f1_score(train_labels, train_pred_bin)
        test_f1  = f1_score(test_labels, test_pred_bin)
        test_auc = roc_auc_score(test_labels, test_preds)

        print(f"Epoch {epoch} | Loss {loss.item():.4f} | "
              f"Train Acc {train_acc:.3f} F1 {train_f1:.3f} | "
              f"Test Acc {test_acc:.3f} F1 {test_f1:.3f} ROC-AUC {test_auc:.3f}")

# -------------------
# Precision@k for top-k risk nodes
# -------------------
def precision_at_k(scores, labels, k=10):
    idx = np.argsort(-scores)[:k]
    return labels[idx].sum() / k

with torch.no_grad():
    all_scores = torch.sigmoid(model(data.x, data.edge_index)).cpu().numpy()
all_labels = data.y.cpu().numpy()
p10 = precision_at_k(all_scores, all_labels, k=10)
p20 = precision_at_k(all_scores, all_labels, k=20)
print(f"Precision@10: {p10:.3f}, Precision@20: {p20:.3f}")

