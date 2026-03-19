# src/models/train_all_models.py

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from tabulate import tabulate

# ----------------------------
# Helper functions
# ----------------------------

def print_metrics(model_name, metrics):
    """
    Nicely format and print the metrics for a model.
    """
    table = [
        ["Accuracy", f"{metrics['accuracy']:.2f}"],
        ["Precision", f"{metrics['precision']:.2f}"],
        ["Recall", f"{metrics['recall']:.2f}"],
        ["F1 Score", f"{metrics['f1_score']:.2f}"]
    ]
    print(f"\n=== {model_name} Metrics ===")
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))

def evaluate_model(model, X_vec, y_true):
    """
    Evaluate a trained model and return metrics.
    """
    y_pred = model.predict(X_vec)
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1_score": f1_score(y_true, y_pred, zero_division=0)
    }
    return metrics

def train_model(model_name, ModelClass, X_train_text, X_test_text, y_train, y_test, **kwargs):
    """
    Train a model with TF-IDF vectorization.
    """
    # Vectorizer
    vectorizer = TfidfVectorizer(stop_words='english')
    X_train_vec = vectorizer.fit_transform(X_train_text)
    X_test_vec = vectorizer.transform(X_test_text)

    # Model
    model = ModelClass(**kwargs)
    model.fit(X_train_vec, y_train)

    # Evaluate
    metrics = evaluate_model(model, X_test_vec, y_test)
    print_metrics(model_name, metrics)

    # Save model and vectorizer
    joblib.dump(model, f"src/models/{model_name.lower()}_model.pkl")
    joblib.dump(vectorizer, f"src/models/{model_name.lower()}_vectorizer.pkl")

    return model, vectorizer, X_test_vec, metrics

# ----------------------------
# Main
# ----------------------------

# Load dataset
df = pd.read_csv("data/processed/emails.csv")

# Drop rows with empty text
df['text'] = df['text'].fillna("")
X = df['text']
y = df['label']

# Split
X_train_full, X_test_full, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train individual models
logistic_model, logistic_vec, _, logistic_metrics = train_model(
    "LogisticRegression", LogisticRegression, 
    X_train_full, X_test_full, y_train, y_test, max_iter=1000, class_weight='balanced'
)

svm_model, svm_vec, _, svm_metrics = train_model(
    "SVM", SVC,
    X_train_full, X_test_full, y_train, y_test, probability=True
)

rf_model, rf_vec, _, rf_metrics = train_model(
    "RandomForest", RandomForestClassifier,
    X_train_full, X_test_full, y_train, y_test, n_estimators=100, random_state=42
)

# Ensemble - Majority Voting
ensemble = VotingClassifier(
    estimators=[
        ('logistic', logistic_model),
        ('svm', svm_model),
        ('rf', rf_model)
    ],
    voting='hard'
)

# Fit ensemble on training data
ensemble.fit(
    logistic_vec.transform(X_train_full),
    y_train
)

ensemble_metrics = evaluate_model(ensemble, logistic_vec.transform(X_test_full), y_test)
print_metrics("Ensemble Model", ensemble_metrics)

# Save ensemble
joblib.dump(ensemble, "src/models/ensemble_model.pkl")

print("\nAll models trained and saved successfully!")