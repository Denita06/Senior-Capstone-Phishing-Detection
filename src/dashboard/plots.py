import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import joblib
import numpy as np
import seaborn as sns
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay


"""
plots.py

This script generates all visualizations for the phishing detection system.

It loads:
- Trained model outputs (metrics.json, predictions)
- Dataset and vectorizer

It produces:
1. Confusion Matrix → model accuracy breakdown
2. Dataset Distribution → class balance
3. Model Comparison → accuracy, precision, recall, F1
4. Random Forest Experiments → tuning impact
5. Feature Importance → most important phishing indicators
6. Correlation Matrix → relationships between features
7. Logistic Regression Experiments → solver comparison

All figures are saved to: src/models/
"""


plt.style.use("seaborn-v0_8")

# =========================
# COLORS (PROFESSIONAL)
# =========================
COLORS = {
    "legit": "#77dd77",
    "phishing": "#ff6f61",
    "palette": [
        "#3B82F6",  # accuracy
        "#34D399",  # precision
        "#FBBF24",  # recall
        "#A78BFA"   # f1
    ]
}

# =========================
# PATHS
# =========================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MODEL_DIR = os.path.join(BASE_DIR, "src/models")
DATA_PATH = os.path.join(BASE_DIR, "src/data/processed/unified_dataset.csv")

df = pd.read_csv(DATA_PATH).dropna(subset=["text", "label"])
vectorizer = joblib.load(os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))

# Load predictions
with open(os.path.join(MODEL_DIR, "test_predictions.json")) as f:
    pred_data = json.load(f)

y = pred_data["y_test"]
preds = pred_data["y_pred"]

# =========================
# FIGURE 1: CONFUSION MATRIX
# =========================
cm = confusion_matrix(y, preds)

disp = ConfusionMatrixDisplay(cm, display_labels=["Legit", "Phishing"])
disp.plot(cmap="Blues")

plt.title("Confusion Matrix", fontsize=14, fontweight="bold")
plt.grid(False)

plt.savefig(os.path.join(MODEL_DIR, "figure_1_confusion_matrix.png"), dpi=300)


# =========================
# FIGURE 2: DISTRIBUTION
# =========================
counts = df["label"].value_counts().sort_index()

plt.figure(figsize=(6, 5))

bars = plt.bar(
    ["Legit", "Phishing"],
    counts.values,
    color=[COLORS["legit"], COLORS["phishing"]]
)

plt.title("Dataset Distribution", fontsize=14, fontweight="bold")
plt.ylabel("Number of Emails")

# Add numbers on bars
for bar in bars:
    plt.text(
        bar.get_x() + bar.get_width()/2,
        bar.get_height(),
        f"{int(bar.get_height()):,}",
        ha="center",
        va="bottom",
        fontweight="bold"
    )

plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "figure_2_distribution.png"), dpi=300)


# =========================
# FIGURE 3: MODEL COMPARISON
# =========================
with open(os.path.join(MODEL_DIR, "metrics.json")) as f:
    metrics = json.load(f)

metrics_df = pd.DataFrame(metrics).T

fig, ax = plt.subplots(figsize=(12, 6))

metrics_df.plot(
    kind="bar",
    color=COLORS["palette"],
    edgecolor="white",
    width=0.8,
    ax=ax
)

plt.title("Model Performance Comparison", fontsize=14, fontweight="bold")
plt.ylabel("Score (0–1)")
plt.xticks(rotation=0)
plt.ylim(0, 1)

# Move legend to top right
plt.legend(
    loc="center left",
    bbox_to_anchor=(1.02, 0.5), # pushed legend outside
    title="Metrics",
    frameon=False
)

# Add values inside bars
for container in ax.containers:
    ax.bar_label(
        container,
        fmt="%.3f",
        fontsize=8,
        label_type="center",
        color="white",
        fontweight="bold"
    )

# Add spacing for legend
plt.subplots_adjust(right=0.8)   

plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "figure_3_comparison.png"), dpi=300)


# =========================
# FIGURE 4: RF TREES (SIMPLIFIED)
# =========================
rf_df = pd.read_json(os.path.join(MODEL_DIR, "rf_experiments.json"))

plt.figure(figsize=(10, 6))
labels_placed = {}

for i, depth in enumerate(sorted(rf_df["depth"].unique(), reverse=True)):
    subset = rf_df[rf_df["depth"] == depth]
    plt.plot(
        subset["n_trees"],
        subset["accuracy"],
        marker="o",
        markersize=8,
        linewidth=2,
        label=f"Depth={depth}",
        alpha=0.7
    )

    for x, y_val in zip(subset["n_trees"], subset["accuracy"]):
        pos_key = (x, round(y_val, 4))

        if pos_key not in labels_placed:
            plt.text(
                x, y_val + 0.02, f'{y_val:.4f}', 
                ha='center', fontsize=8, fontweight='bold',
                bbox=dict(facecolor='white', alpha=0.5, edgecolor='none', pad=1))
            labels_placed[pos_key] = True

plt.title("Random Forest: Trees vs Accuracy", fontweight="bold", fontsize=14)
plt.xlabel("Number of Trees")
plt.ylabel("Accuracy")
plt.ylim(0, 1.1)
plt.axhline(y=0.9963, color='black', linestyle='--', alpha=0.5, label='Ensemble Accuracy')
plt.legend(loc="center left", bbox_to_anchor=(1, 0.5))
plt.grid(alpha=0.2)
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "figure_4_rf_trees.png"), dpi=300)


# =========================
# FIGURE 5: RF DEPTH (SIMPLIFIED)
# =========================
plt.figure(figsize=(10, 6))
labels_placed = {}

for i, trees in enumerate(sorted(rf_df["n_trees"].unique(), reverse=True)):
    subset = rf_df[rf_df["n_trees"] == trees]
    plt.plot(
        subset["depth"],
        subset["accuracy"],
        marker="o",
        markersize=8,
        linewidth=2,
        label=f"Trees={trees}",
        alpha=0.7
    )

    for x, y_val in zip(subset["depth"], subset["accuracy"]):
        pos_key = (x, round(y_val, 4))
        if pos_key not in labels_placed:
            plt.text(
                x, y_val + 0.01, f'{y_val:.4f}',
                ha='center', fontsize=8, fontweight='bold',
                bbox=dict(facecolor='white', alpha=0.5, edgecolor='none', pad=1))
            labels_placed[pos_key] = True


plt.title("Random Forest: Depth vs Accuracy", fontweight="bold", fontsize=14)
plt.xlabel("Tree Depth")
plt.ylabel("Accuracy")
plt.ylim(0, 1.1)

plt.axhline(y=0.9963, color='black', linestyle='--', alpha=0.5, label='Ensemble Accuracy')

plt.legend(loc="center left", bbox_to_anchor=(1, 0.5))
plt.grid(alpha=0.2)

plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "figure_5_rf_depth.png"), dpi=300)


# =========================
# FIGURE 6: ACCURACY ONLY (CLEAN)
# =========================
accuracy_df = metrics_df[["accuracy"]]

fig, ax = plt.subplots(figsize=(8, 6))

bars = ax.bar(
    accuracy_df.index,
    accuracy_df["accuracy"],
    color=COLORS["palette"][0]
)

plt.title("Model Accuracy Comparison", fontweight="bold")
plt.ylabel("Accuracy (0–1)")
plt.ylim(0, 1.2)

# Add values
for bar in bars:
    ax.text(
        bar.get_x() + bar.get_width()/2,
        bar.get_height() + 0.01,
        f"{bar.get_height():.4f}",
        ha="center",
        va="bottom",
        fontweight="bold"
    )

plt.xticks(rotation=45, ha='right')

plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "figure_6_accuracy_only.png"), dpi=300)


# =========================
# FIGURE 7: FEATURE IMPORTANCE
# =========================
rf_model = joblib.load(os.path.join(MODEL_DIR, "Random Forest_model.pkl"))

importance = rf_model.feature_importances_
indices = np.argsort(importance)[-15:]

features = vectorizer.get_feature_names_out()

plt.figure(figsize=(7, 5))

plt.barh(
    range(len(indices)),
    importance[indices],
    color=COLORS["palette"][1]
)

plt.yticks(range(len(indices)), [features[i] for i in indices])
plt.title("Top Features (Random Forest)", fontweight="bold")

plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "figure_7_feature_importance.png"), dpi=300)



# =========================
# FIGURE 8: CORRELATION MATRIX (top N features)
# =========================

# 1. Define how many top features you want to see
top_n = 10 

# 2. Recreate X_vec from the text data
X_vec = vectorizer.transform(df["text"])

# 3. Get the indices of the most important features from the Random Forest
# Make sure you have loaded 'rf_model' and 'features' earlier in the script!
top_indices = np.argsort(rf_model.feature_importances_)[-top_n:]
top_feature_names = [features[i] for i in top_indices]

# 4. Create a DataFrame for the correlation calculation
X_top = pd.DataFrame(
    X_vec[:, top_indices].toarray(), 
    columns=top_feature_names
)

# 5. Generate the heatmap
plt.figure(figsize=(10, 8))
sns.heatmap(X_top.corr(), annot=True, cmap="coolwarm", fmt=".2f", center=0)
plt.title(f"Correlation Matrix: Top {top_n} Phishing Indicators", fontweight="bold")
plt.tight_layout()

# 6. Save the figure
plt.savefig(os.path.join(MODEL_DIR, "figure_8_correlation_matrix.png"), dpi=300)


# =========================
# FIGURE 9: LR Optimizer Comparison
# =========================

lr_exp = pd.read_json(os.path.join(MODEL_DIR, "lr_optimizer_experiments.json"))

fig, ax = plt.subplots(figsize=(8, 6))
bars = ax.bar(lr_exp["solver"], lr_exp["accuracy"], color=COLORS["palette"][2])
plt.title("Logistic Regression: Optimizer Comparison", fontweight="bold")
plt.ylabel("Accuracy (0–1)")
plt.ylim(0, 1.1)
for bar in bars:
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
            f"{bar.get_height():.4f}", ha="center", va="bottom", fontweight="bold")
    
plt.xticks(rotation=0, ha='center')

plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "figure_9_lr_optimizers.png"), dpi=300)


print("\n✅ All plots generated successfully!")