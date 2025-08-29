# -------------------
# Step 1: Load datasets safely and save to disk
# -------------------
import pandas as pd, json, os, glob

BASE_DIR = "/content/drive/MyDrive/combined_datasets_backup"
SAVE_DIR = "/content/drive/MyDrive/processed_datasets"
os.makedirs(SAVE_DIR, exist_ok=True)

# -------------------
# DiverseVul
# -------------------
diverse_file = os.path.join(BASE_DIR, "diversevul_20230702.json")
df_diversevul = pd.DataFrame()
if os.path.exists(diverse_file):
    try:
        df_diversevul = pd.read_json(diverse_file, lines=True)
    except ValueError:
        rows = []
        with open(diverse_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
        df_diversevul = pd.DataFrame(rows)
    df_diversevul = df_diversevul.rename(columns={
        "code": "raw_code",
        "vuln_label": "label",
        "cve_id": "cve"
    })
    if "label" in df_diversevul.columns:
        df_diversevul["label"] = df_diversevul["label"].astype(int)
df_diversevul.to_pickle(os.path.join(SAVE_DIR, "df_diversevul.pkl"))
print(f"✅ DiverseVul saved: {len(df_diversevul)} rows")

# -------------------
# Devign (parquet from HF)
# -------------------
devign_file = os.path.join(BASE_DIR, "devign_dataset_from_hf.parquet")
df_devign = pd.DataFrame()
if os.path.exists(devign_file):
    df_devign = pd.read_parquet(devign_file)
    # Convert target/label to binary
    def process_label(x):
        try:
            if isinstance(x, (int, float)):
                return int(x>0)
            elif isinstance(x, (list, tuple, pd.Series)):
                return int(any([bool(y) for y in x]))
        except:
            return 0
    if "target" in df_devign.columns:
        df_devign["label"] = df_devign["target"].apply(process_label)
    df_devign = df_devign.rename(columns={"code":"raw_code"})
df_devign.to_pickle(os.path.join(SAVE_DIR, "df_devign.pkl"))
print(f"✅ Devign saved: {len(df_devign)} rows")

# -------------------
# NVD (2021–2025 JSON)
# -------------------
df_nvd = pd.DataFrame()
nvd_files = sorted(glob.glob(os.path.join(BASE_DIR, "nvdcve-2.0-20*.json")))
for f in nvd_files:
    with open(f, "r", encoding="utf-8") as g:
        data = json.load(g)
    if "vulnerabilities" in data:
        # Flatten nested structures
        rows = []
        for v in data["vulnerabilities"]:
            row = {}
            cve = v.get("cve", {})
            row["cve"] = cve.get("id")
            row["description"] = "; ".join([d.get("value","") for d in cve.get("descriptions", [])])
            # CVSS v3.1 base score
            cvss31 = cve.get("metrics", {}).get("cvssMetricV31", [])
            row["cvss"] = cvss31[0]["cvssData"]["baseScore"] if cvss31 else 0.0
            rows.append(row)
        df_nvd = pd.concat([df_nvd, pd.DataFrame(rows)], ignore_index=True)
df_nvd.to_pickle(os.path.join(SAVE_DIR, "df_nvd.pkl"))
print(f"✅ NVD saved: {len(df_nvd)} rows from {len(nvd_files)} files")

# -------------------
# OSV (skip empty files)
# -------------------
df_osv = pd.DataFrame()
osv_records = []
for file in glob.glob(os.path.join(BASE_DIR, "osv_all", "*.json")):
    if os.path.getsize(file) == 0:
        print(f"⚠️ Skipping empty OSV file: {file}")
        continue
    try:
        osv_records.append(json.load(open(file)))
    except json.JSONDecodeError:
        print(f"⚠️ Skipping invalid JSON OSV file: {file}")
if osv_records:
    df_osv = pd.json_normalize(osv_records)
df_osv.to_pickle(os.path.join(SAVE_DIR, "df_osv.pkl"))
print(f"✅ OSV saved: {len(df_osv)} rows")

# -------------------
# EPSS (CSV)
# -------------------
epss_file = os.path.join(BASE_DIR, "cve_cisa_epss_enriched_dataset.csv")
df_epss = pd.DataFrame()
if os.path.exists(epss_file):
    df_epss = pd.read_csv(epss_file)
    df_epss = df_epss.rename(columns={"CVE":"cve","EPSS":"epss"})
df_epss.to_pickle(os.path.join(SAVE_DIR, "df_epss.pkl"))
print(f"✅ EPSS saved: {len(df_epss)} rows")

# -------------------
# KEV
# -------------------
kev_file = os.path.join(BASE_DIR, "known_exploited_vulnerabilities.json")
kev_cves = set()
if os.path.exists(kev_file):
    kev_data = json.load(open(kev_file, "r"))
    kev_cves = {item["cveID"] for item in kev_data.get("vulnerabilities", [])}
print(f"✅ KEV loaded: {len(kev_cves)} CVEs")
