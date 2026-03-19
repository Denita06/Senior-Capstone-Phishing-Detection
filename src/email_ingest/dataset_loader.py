import os
import pandas as pd
from .parser import parse_eml
from src.config.paths import RAW_DATA_PATH, PROCESSED_DATA_PATH, LOG_PATH


def log_error(file, error):
    """
    Logs corrupted or unreadable files.
    """
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(f"{file}: {error}\n")


def load_dataset():
    """
    Loads emails from raw dataset, parses them, and assigns labels.

    Returns:
        texts (list): email contents
        labels (list): 0 (legitimate) or 1 (phishing)
    """
    texts = []
    labels = []

    legitimate_path = os.path.join(RAW_DATA_PATH, "legitimate")
    phishing_path = os.path.join(RAW_DATA_PATH, "phishing")

    # Process legitimate emails
    for file in os.listdir(legitimate_path):
        file_path = os.path.join(legitimate_path, file)

        try:
            text = parse_eml(file_path)
            texts.append(text)
            labels.append(0)  # legitimate

        except Exception as e:
            log_error(file, str(e))

    # Process phishing emails
    for file in os.listdir(phishing_path):
        file_path = os.path.join(phishing_path, file)

        try:
            text = parse_eml(file_path)
            texts.append(text)
            labels.append(1)  # phishing

        except Exception as e:
            log_error(file, str(e))

    return texts, labels


def save_dataset(texts, labels):
    """
    Saves processed dataset as a CSV file for training.
    """
    df = pd.DataFrame({
        "text": texts,
        "label": labels
    })

    # Ensure processed folder exists
    os.makedirs(PROCESSED_DATA_PATH, exist_ok=True)

    output_path = os.path.join(PROCESSED_DATA_PATH, "emails.csv")

    df.to_csv(output_path, index=False)

    print(f"Dataset saved to {output_path}")