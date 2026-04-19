import os
import pandas as pd


def load_kaggle():
    """
    Load and standardize SpamAssassin dataset into:
    - text
    - label
    """

    BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
    )

    # ✅ Updated path to existing dataset
    path = os.path.join(
        BASE_DIR,
        "data/raw/spamassassin/SpamAssassin.csv"
    )

    print(f"📥 Loading SpamAssassin dataset from: {path}")

    # Safety check
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found at: {path}")

    df = pd.read_csv(path)

    # -----------------------------
    # Normalize TEXT column
    # -----------------------------
    if "text" in df.columns:
        pass
    elif "message" in df.columns:
        df["text"] = df["message"]
    elif "body" in df.columns:
        df["text"] = df["body"]
    else:
        raise ValueError(
            f"❌ No text column found. Columns: {list(df.columns)}"
        )

    # -----------------------------
    # Normalize LABEL column
    # -----------------------------
    if "label" in df.columns:
        pass
    elif "class" in df.columns:
        df["label"] = df["class"]
    elif "Category" in df.columns:
        df["label"] = df["Category"]
    else:
        raise ValueError(
            f"❌ No label column found. Columns: {list(df.columns)}"
        )

    # Keep only required columns
    df = df[["text", "label"]]

    df = df.dropna().reset_index(drop=True)

    print(f"SpamAssassin loaded: {df.shape}")

    return df