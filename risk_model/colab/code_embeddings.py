# -------------------
# 2.2 Load datasets
# -------------------
df_diversevul = pd.read_pickle(os.path.join(SAVE_DIR, "df_diversevul.pkl"))
df_devign    = pd.read_pickle(os.path.join(SAVE_DIR, "df_devign.pkl"))
df_nvd       = pd.read_pickle(os.path.join(SAVE_DIR, "df_nvd.pkl"))
df_osv       = pd.read_pickle(os.path.join(SAVE_DIR, "df_osv.pkl"))

# -------------------
# 2.3 CodeBERT embeddings
# -------------------
device = 'cuda' if torch.cuda.is_available() else 'cpu'
tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
model = AutoModel.from_pretrained("microsoft/codebert-base").to(device)

def get_code_embedding(code):
    try:
        inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
        return outputs.last_hidden_state.mean(dim=1).cpu().numpy().flatten()
    except:
        return np.zeros(768, dtype=np.float32)

# -------------------
# 2.4 Apply embeddings (example: first 100 rows per dataset)
# -------------------
for df, name in [(df_diversevul, "diversevul"), (df_devign, "devign")]:
    if "raw_code" in df.columns:
        df['code_emb'] = df['raw_code'].iloc[:100].apply(get_code_embedding)  # for demo, change as needed
        df.to_pickle(os.path.join(SAVE_DIR, f"df_{name}_with_emb.pkl"))
        print(f"✅ Code embeddings added for {name}")
