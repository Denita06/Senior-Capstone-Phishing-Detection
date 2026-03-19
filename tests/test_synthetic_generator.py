import pandas as pd
from src.email_ingest.synthetic_generator import generate_synthetic_data

def test_synthetic_data_generation():
    data = {
        "subject": ["Hello"],
        "url": ["https://example.com"],
        "sender": ["user@example.com"],
        "label": [0]
    }

    df = pd.DataFrame(data)

    synthetic_df = generate_synthetic_data(df, num_samples=5)

    assert len(synthetic_df) == 5


def test_labels_preserved():
    data = {
        "subject": ["Test"],
        "url": ["https://example.com"],
        "sender": ["user@example.com"],
        "label": [1]
    }

    df = pd.DataFrame(data)

    synthetic_df = generate_synthetic_data(df, num_samples=5)

    assert all(synthetic_df['label'] == 1)