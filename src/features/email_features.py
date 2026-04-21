from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

from src.features.url_analysis import analyze_urls


# -----------------------------
# TEXT FEATURE ENGINE (TF-IDF)
# -----------------------------
def create_vectorizer():
    """
    Creates TF-IDF vectorizer for email text.
    Captures word + phrase-level phishing patterns.
    """
    return TfidfVectorizer(
        stop_words='english',
        max_features=2000,
        ngram_range=(1, 2)
    )


# -----------------------------------
# COMBINED FEATURE EXTRACTION (CORE)
# -----------------------------------
def extract_email_features(text):
    """
    Extracts ALL non-text-based phishing features.

    This includes:
    - URL structure signals
    - obfuscation patterns
    - domain behavior
    """

    url_features = analyze_urls(text)

    return np.array([
        url_features["url_count"],
        url_features["unique_domains"],
        url_features["has_ip_url"],
        url_features["has_shortener"],
        url_features["has_suspicious_tld"],
        url_features["avg_url_length"]
    ]).reshape(1, -1)


# -----------------------------------
# FEATURE NAME TRACKING (OPTIONAL BUT USEFUL)
# -----------------------------------
def get_feature_names():
    """
    Helps with debugging / model interpretability.
    """
    return [
        "url_count",
        "unique_domains",
        "has_ip_url",
        "has_shortener",
        "has_suspicious_tld",
        "avg_url_length"
    ]