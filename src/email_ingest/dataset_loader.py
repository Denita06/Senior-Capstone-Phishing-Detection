import os
from .parser import parse_eml

def load_dataset(base_path):
    texts = []
    labels = []

    # Process legitimate emails first
    legitimate_path = os.path.join(base_path, "legitimate")
    for file in os.listdir(legitimate_path):
        file_path = os.path.join(legitimate_path, file)
        texts.append(parse_eml(file_path))
        labels.append(0) # 0 = legitimate

    # Process phishing emails
    phishing_path = os.path.join(base_path, "phishing")
    for file in os.listdir(phishing_path):
        file_path = os.path.join(phishing_path, file)
        texts.append(parse_eml(file_path))
        labels.append(1) # 1 = phishing

    #Return all email text and corresponding labels
    return texts, labels