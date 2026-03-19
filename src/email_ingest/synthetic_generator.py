# src/email_ingest/synthetic_generator.py

import pandas as pd
import random
import os

# Simple word replacements for variation
SUBJECT_PREFIXES = ["URGENT:", "Action Required:", "Important:", "Notice:"]
PHISHING_DOMAINS = ["secure-login.com", "verify-account.net", "update-info.org"]
LEGIT_DOMAINS = ["company.com", "service.org", "officialsite.com"]

def modify_subject(subject):
    if random.random() > 0.5:
        return random.choice(SUBJECT_PREFIXES) + " " + subject
    return subject

def modify_url(label):
    if label == 1:
        return "http://" + random.choice(PHISHING_DOMAINS)
    else:
        return "https://" + random.choice(LEGIT_DOMAINS)

def modify_sender(label):
    if label == 1:
        return f"support@{random.choice(PHISHING_DOMAINS)}"
    else:
        return f"noreply@{random.choice(LEGIT_DOMAINS)}"

def generate_synthetic_data(df, num_samples=100):
    synthetic_rows = []

    for _ in range(num_samples):
        row = df.sample(1).iloc[0]

        new_row = row.copy()

        new_row['subject'] = modify_subject(row['subject'])
        new_row['url'] = modify_url(row['label'])
        new_row['sender'] = modify_sender(row['label'])

        synthetic_rows.append(new_row)

    synthetic_df = pd.DataFrame(synthetic_rows)

    return synthetic_df


def save_synthetic_data(df, output_path="data/processed/synthetic_emails.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Synthetic dataset saved to {output_path}")


if __name__ == "__main__":
    print("Loading dataset...")
    df = pd.read_csv("data/raw/emails.csv")

    print("Generating synthetic data...")
    synthetic_df = generate_synthetic_data(df, num_samples=200)

    print("Saving synthetic data...")
    save_synthetic_data(synthetic_df)