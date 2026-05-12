import os
import pandas as pd
import joblib
import json

# Machine Learning utilities for splitting, validation, and evaluation
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
# Converts raw text --> numerical features using TF-IDF
from sklearn.feature_extraction.text import TfidfVectorizer
# ML models used in this project
from sklearn.linear_model import LogisticRegression   # Linear model for classification
from sklearn.svm import SVC                     # Support Vector Machine (fast for text)
from sklearn.ensemble import RandomForestClassifier, VotingClassifier   # Tree-based + ensemble
from sklearn.naive_bayes import MultinomialNB  # Probalistic model (best for text)
# Evaluation metrics
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


# =========================
# 1. PATH SETUP
# =========================

# Get project root directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# Path to processed dataset
DATA_PATH = os.path.join(BASE_DIR, "src/data/processed/unified_dataset.csv")

# Folder to store models + outputs
MODEL_DIR = os.path.join(BASE_DIR, "src/models")

# Ensure model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)


# =========================
# 2. LOAD DATA
# =========================

print("Loading dataset...")

# Load only necessary columns (memory efficient)
df = pd.read_csv(
    DATA_PATH,
    usecols=["text", "label"],
    # dtype={"text": "string", "label": "int8"}
)

# Remove missing values
df = df.dropna()

print("Dataset shape:", df.shape)
print("\nClass distribution:\n", df["label"].value_counts())

# =========================
# 3. SPEED OPTIMIZATION (SAMPLING)
# =========================

# Limit dataset size to speed up training
MAX_SAMPLES = 200000

if len(df) > MAX_SAMPLES:
    print(f"\n⚡ Sampling dataset down to {MAX_SAMPLES} rows...")
    df = df.sample(MAX_SAMPLES, random_state=42).reset_index(drop=True)

# =========================
# 4. TEXT VECTORIZATION
# =========================

print("\nVectorizing text...")

# X = input text, y = labels (0 = legit, 1 = phishing)
X = df["text"]
y = df["label"]

# Convert text → numeric matrix using TF-IDF
# - Includes unigrams + bigrams
# - Limits features to top 5000 most important words
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    min_df=3,
    stop_words="english"
)

# Transform text into numerical vectors
X_vec = vectorizer.fit_transform(X)

# Save vectorizer for future predictions
vectorizer_path = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
joblib.dump(vectorizer, vectorizer_path)

print(f"Vectorizer saved at: {vectorizer_path}")

# =========================
# 5. TRAIN / TEST SPLIT
# =========================

# Split data into training (80%) and testing (20%)
# Stratified = preserves class balance
X_train, X_test, y_train, y_test = train_test_split(
    X_vec,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# =========================
# 6. DEFINE MODELS
# =========================

"""
MODEL EXPLANATIONS:

1. Logistic Regression:
   - Linear model
   - Good baseline for classification
   - Works well with TF-IDF text data

2. Support Vector Machine (SVM):
   - Finds best boundary between classes
   - Very effective in high-dimensional spaces (like text)

3. Random Forest:
   - Ensemble of decision trees
   - Captures complex, non-linear patterns

4. Naive Bayes:
   - Probabilistic model
   - Assumes word independence
   - Very fast and strong for text classification
"""

models = {
    "Logistic": LogisticRegression(
        solver="saga",
        max_iter=500,
        class_weight="balanced"
    ),

    "Support Vector Machine (SVM)": SVC(
        kernel='rbf',
        probability=True,
        class_weight="balanced",
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=80,
        max_depth=20,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample"
    ),

    "Naive Bayes": MultinomialNB()
}

# =========================
# 7. CROSS VALIDATION 
# =========================

print("\n=== Cross Validation ===")

# Stratified K-Fold ensures balanced splits
skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

# Evaluate models using F1-score (important for phishing detection)
for name, model in models.items():
    scores = cross_val_score(model, X_vec, y, cv=skf, scoring="f1", n_jobs=-1)
    print(f"{name}: F1 = {scores.mean():.3f} (+/- {scores.std():.3f})")

# =========================
# 8. TRAIN INDIVIDUAL MODELS
# =========================

print("\nTraining models...\n")

metrics_summary = {}

for name, model in models.items():
    # Train model
    model.fit(X_train, y_train)

    # Predict on test data
    preds = model.predict(X_test)

    # Display evaluation results
    print(f"\n=== {name.upper()} ===")
    print("Accuracy:", accuracy_score(y_test, preds))
    print(classification_report(y_test, preds))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))

    # Save trained model
    model_path = os.path.join(MODEL_DIR, f"{name}_model.pkl")
    joblib.dump(model, model_path)
    print(f"✅ Saved: {model_path}")

    # Save metrics
    report = classification_report(y_test, preds, output_dict=True)

    metrics_summary[name] = {
        "accuracy": float(accuracy_score(y_test, preds)),
        "precision": float(report["1"]["precision"]),
        "recall": float(report["1"]["recall"]),
        "f1": float(report["1"]["f1-score"])
    }

# =========================
# 9. ENSEMBLE MODEL (HARD VOTING)
# =========================

"""
Ensemble Model:
- Combines predictions from all models
- Uses "hard voting" → majority vote
- Improves overall accuracy and robustness
"""

print("\nTraining Ensemble...\n")

ensemble = VotingClassifier(
    estimators=[
        ("lr", models["Logistic"]),
        ("svm", models["Support Vector Machine (SVM)"]),
        ("rf", models["Random Forest"]),
        ("nb", models["Naive Bayes"])
    ],
    voting="hard"   # faster than soft
)

ensemble.fit(X_train, y_train)
ensemble_preds = ensemble.predict(X_test)

print("=== ENSEMBLE ===")
print("Accuracy:", accuracy_score(y_test, ensemble_preds))
print(classification_report(y_test, ensemble_preds))
print("Confusion Matrix:")
print(confusion_matrix(y_test, ensemble_preds))

# Save ensemble model
ensemble_path = os.path.join(MODEL_DIR, "ensemble_model.pkl")
joblib.dump(ensemble, ensemble_path)

print(f"✅ Saved: {ensemble_path}")

# Save ensemble metrics
report = classification_report(y_test, ensemble_preds, output_dict=True)

metrics_summary["Ensemble"] = {
    "accuracy": float(accuracy_score(y_test, ensemble_preds)),
    "precision": float(report["1"]["precision"]),
    "recall": float(report["1"]["recall"]),
    "f1": float(report["1"]["f1-score"])
}


# =========================
# 10. SAVE TEST PREDICTIONS 
# =========================

# Save predictions for visualization later
with open(os.path.join(MODEL_DIR, "test_predictions.json"), "w") as f:
    json.dump({
        "y_test": y_test.tolist(),
        "y_pred": ensemble_preds.tolist()
    }, f)


# =========================
# 11. RANDOM FOREST EXPERIMENTS
# =========================

"""
Experiment:
Test how number of trees and depth affect accuracy
"""

print("\nRunning Random Forest Experiments...\n")

rf_results = []

depths = [5, 10, 20]
n_trees = [10, 50, 100, 200]

for depth in depths:
    for n in n_trees:
        rf = RandomForestClassifier(
            n_estimators=n,
            max_depth=depth,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced_subsample"
        )

        rf.fit(X_train, y_train)
        preds = rf.predict(X_test)

        acc = accuracy_score(y_test, preds)

        rf_results.append({
            "depth": depth,
            "n_trees": n,
            "accuracy": float(acc)
        })

# =========================
# 12. LOGISTIC REGRESSION EXPERIMENTS
# =========================

"""
Test different solvers for Logistic Regression
"""

print("\nRunning Logistic Regression Optimizer Experiments...\n")

lr_results = []
solvers = ["lbfgs", "saga", "liblinear", "newton-cg"]

for solver in solvers:
    try:
        lr = LogisticRegression(solver=solver, max_iter=500, class_weight="balanced")
        lr.fit(X_train, y_train)
        preds = lr.predict(X_test)
        acc = accuracy_score(y_test, preds)
        lr_results.append({"solver": solver, "accuracy": float(acc)})
        print(f"  {solver}: {acc:.4f}")
    except Exception as e:
        print(f"  {solver} failed: {e}")

with open(os.path.join(MODEL_DIR, "lr_optimizer_experiments.json"), "w") as f:
    json.dump(lr_results, f, indent=4)


# Save experiment results
rf_exp_path = os.path.join(MODEL_DIR, "rf_experiments.json")

with open(rf_exp_path, "w") as f:
    json.dump(rf_results, f, indent=4)

print(f"🌲 RF Experiments saved at: {rf_exp_path}")

# =========================
# 10. SAVE METRICS FILE
# =========================

metrics_path = os.path.join(MODEL_DIR, "metrics.json")

with open(metrics_path, "w") as f:
    json.dump(metrics_summary, f, indent=4)

print(f"📊 Metrics saved at: {metrics_path}")
print("\n✅ Training Complete!")

