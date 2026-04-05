import pandas as pd

def load_nazario(path="src/data/raw/nazario/phishing-2025.txt"):
    emails = []

    with open(path, "r", encoding="latin-1") as file:
        content = file.read()

        # Split emails (Nazario uses separators like this)
        raw_emails = content.split("\n\n\n")

        for email in raw_emails:
            email = email.strip()
            if len(email) > 50:  # filter noise
                emails.append(email)

    df = pd.DataFrame({"text": emails})
    df["label"] = 1
    df["source"] = "nazario"

    return df