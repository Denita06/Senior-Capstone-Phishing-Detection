import os
import pandas as pd


def _standardize(df):
    """
    Normalize dataset columns to:
    - text
    - label
    """

    # -------- TEXT --------
    if "text" in df.columns:
        pass
    elif "message" in df.columns:
        df["text"] = df["message"]
    elif "body" in df.columns:
        df["text"] = df["body"]
    elif "content" in df.columns:
        df["text"] = df["content"]
    else:
        raise ValueError(f"No text column found: {list(df.columns)}")

    # -------- LABEL --------
    if "label" in df.columns:
        pass
    elif "class" in df.columns:
        df["label"] = df["class"]
    elif "Category" in df.columns:
        df["label"] = df["Category"]
    elif "category" in df.columns:
        df["label"] = df["category"]
    else:
        raise ValueError(f"No label column found: {list(df.columns)}")

    df = df[["text", "label"]]
    df = df.dropna().reset_index(drop=True)

    return df


def load_kaggle():
    """
    Kaggle dataset = SpamAssassin + Nigerian Fraud + CEAS-08
    """

    BASE_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../..")
    )

    paths = {
        "spamassassin": os.path.join(
            BASE_DIR, "data/raw/spamassassin/SpamAssassin.csv"
        ),
        "nigerian_fraud": os.path.join(
            BASE_DIR, "data/raw/nigerian_fraud/Nigerian_Fraud.csv"
        ),
        "ceas_08": os.path.join(
            BASE_DIR, "data/raw/ceas_08/CEAS_08.csv"
        ),
    }

    datasets = []

    print("📥 Loading Kaggle composite datasets...")

    for name, path in paths.items():
        if not os.path.exists(path):
            raise FileNotFoundError(f"{name} dataset missing at: {path}")

        print(f"   → Loading {name}: {path}")

        df = pd.read_csv(path, encoding="latin-1")
        df = df.loc[:, ~df.columns.str.contains("^Unnamed")]

        df = _standardize(df)

        print(f"   ✅ {name} loaded: {df.shape}")
        datasets.append(df)

    # -----------------------------
    # Combine datasets
    # -----------------------------
    combined = pd.concat(datasets, ignore_index=True)

    print(f"✅ Kaggle combined dataset: {combined.shape}")

    return combined