import os
import pandas as pd

# =========================================================
# BASE PATH (robust for module execution)
# =========================================================
BASE_DIR = os.path.abspath(os.getcwd())

# =========================================================
# CENTRALIZED PATH CONFIG (NEW CLEAN STRUCTURE)
# =========================================================
DATA_DIR = os.path.join(BASE_DIR, "src/data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Ensure directories exist
os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# =========================================================
# IMPORT LOADERS
# =========================================================
from src.data.loaders.enron_loader import load_enron
from src.data.loaders.nazario_loader import load_nazario
from src.data.loaders.fraud_loader import load_fraud
from src.data.loaders.kaggle_loader import load_kaggle

# Optional loaders (safe import)
try:
    from src.data.loaders.ceas_loader import load_ceas
except:
    load_ceas = None

try:
    from src.data.loaders.nigerian_loader import load_nigerian
except:
    load_nigerian = None

# =========================================================
# 1. LOAD DATASETS
# =========================================================
print("🔄 Loading datasets via loaders...\n")

enron_df = load_enron()
nazario_df = load_nazario()
fraud_df = load_fraud()
kaggle_df = load_kaggle()

datasets = [
    ("enron", enron_df),
    ("nazario", nazario_df),
    ("fraud_corpus", fraud_df),
    ("kaggle", kaggle_df),
]

if load_ceas:
    datasets.append(("ceas_08", load_ceas()))

if load_nigerian:
    datasets.append(("nigerian_fraud", load_nigerian()))

# =========================================================
# 2. ASSIGN SOURCE LABELS
# =========================================================
print("🏷️ Assigning dataset sources...")

cleaned_dfs = []

for name, df in datasets:
    df = df.copy()
    df["source"] = name
    cleaned_dfs.append(df)

# =========================================================
# 3. COMBINE DATASETS
# =========================================================
print("\n📊 Combining datasets...")

df = pd.concat(cleaned_dfs, ignore_index=True)

# =========================================================
# 4. VALIDATE SCHEMA
# =========================================================
required_cols = {"text", "label", "source"}

missing = required_cols - set(df.columns)
if missing:
    raise ValueError(f"Missing required columns: {missing}")

df = df[["text", "label", "source"]]

# =========================================================
# 5. CLEANING PIPELINE
# =========================================================
print("🧹 Cleaning dataset...")

df["text"] = df["text"].fillna("")
df["source"] = df["source"].fillna("unknown")

# remove empty rows
df = df[df["text"].str.strip().astype(bool)]

# optional filter (recommended)
df = df[df["text"].str.len() > 20]

# normalize whitespace
df["text"] = df["text"].str.replace(r"\s+", " ", regex=True)

# =========================================================
# 6. REMOVE DUPLICATES
# =========================================================
before = len(df)
df = df.drop_duplicates(subset=["text"])
after = len(df)

print(f"🧽 Removed duplicates: {before - after}")

# =========================================================
# 7. LABEL VALIDATION
# =========================================================
print("\n🔍 Validating labels...")

print(df["label"].value_counts())

assert set(df["label"].unique()).issubset({0, 1}), "Invalid labels detected!"

df["label"] = df["label"].astype(int)

# =========================================================
# 8. DATASET ANALYSIS REPORT
# =========================================================
print("\n📈 Dataset Summary\n")

print("Label distribution:")
print(df["label"].value_counts())

print("\nSource distribution:")
print(df["source"].value_counts())

print("\nClass balance (%):")
print(df["label"].value_counts(normalize=True) * 100)

# Save report
report_path = os.path.join(REPORTS_DIR, "dataset_summary.txt")

with open(report_path, "w") as f:
    f.write("=== UNIFIED DATASET REPORT ===\n\n")
    f.write(f"Total rows: {len(df)}\n\n")
    f.write("Label distribution:\n")
    f.write(str(df["label"].value_counts()) + "\n\n")
    f.write("Source distribution:\n")
    f.write(str(df["source"].value_counts()) + "\n\n")
    f.write("Class balance (%):\n")
    f.write(str(df["label"].value_counts(normalize=True) * 100))

print(f"\n📄 Report saved → {report_path}")

# =========================================================
# 9. SAVE FINAL PROCESSED DATASET
# =========================================================
output_path = os.path.join(PROCESSED_DIR, "unified_dataset.csv")

df.to_csv(output_path, index=False)

print(f"\n✅ Saved unified dataset → {output_path}")