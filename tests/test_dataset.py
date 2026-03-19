from src.config.paths import PROCESSED_DATA_PATH
import os
import pandas as pd


def test_dataset_exists():
    path = os.path.join(PROCESSED_DATA_PATH, "emails.csv")
    assert os.path.exists(path)


def test_labels_valid():
    path = os.path.join(PROCESSED_DATA_PATH, "emails.csv")
    df = pd.read_csv(path)
    assert set(df["label"]).issubset({0, 1})


def test_no_empty_text():
    path = os.path.join(PROCESSED_DATA_PATH, "emails.csv")
    df = pd.read_csv(path)
    assert df["text"].str.strip().ne("").all()