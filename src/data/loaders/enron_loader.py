import pandas as pd

def load_enron(path="src/data/raw/enron/emails.csv"):
    df = pd.read_csv(path)

    # Combine subject + body if available
    if "subject" in df.columns and "message" in df.columns:
        df["text"] = df["subject"].fillna("") + " " + df["message"].fillna("")
    elif "message" in df.columns:
        df["text"] = df["message"]
    else:
        raise ValueError("Enron dataset missing expected columns")

    df["label"] = 0
    df["source"] = "enron"

    return df[["text", "label", "source"]]