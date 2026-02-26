import os
from .parser import parse_eml

def load_dataset(base_path):
    texts = []
    labels = []

    legitimate_path = os.path.join(base_path, "legitimate")
    phishing_path = os.path.join(base_path, "phishing")

    # Legitimate = 0
    for file in os.listdir(legitimate_path):
        file_path = os.path.join(legitimate_path, file)
        texts.append(parse_eml(file_path))
        labels.append(0)

    # Phishing = 1
    for file in os.listdir(phishing_path):
        file_path = os.path.join(phishing_path, file)
        texts.append(parse_eml(file_path))
        labels.append(1)

    return texts, labels