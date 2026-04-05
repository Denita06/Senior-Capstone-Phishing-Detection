import pandas as pd

def load_fraud():
    df = pd.read_csv("src/data/raw/fraudulent_email_corpus/phishing_emails.csv")

    if "text" in df.columns:
        df["text"] = df["text"]
    else:
        df["text"] = df.iloc[:, 0]

    df["label"] = 1
    df["source"] = "fraud_corpus"

    return df[["text", "label", "source"]]