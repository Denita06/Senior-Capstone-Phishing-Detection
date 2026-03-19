import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from scipy.sparse import hstack
import joblib
import logging
import os

# Logging setup
logging.basicConfig(filename='logs/model_training.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# CSV path
csv_path = 'data/processed/emails.csv'
if not os.path.exists(csv_path):
    raise FileNotFoundError(f"{csv_path} not found. Make sure the processed CSV exists.")

# Load dataset
df = pd.read_csv(csv_path)

# Separate label
y = df['label']

# Process text features
vectorizer = TfidfVectorizer(max_features=1000)
X_text = vectorizer.fit_transform(df['content'])

# Process numeric/categorical features
numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
numeric_cols = [c for c in numeric_cols if c != 'label']
X_numeric = df[numeric_cols].values if numeric_cols else None

# Combine features
if X_numeric is not None:
    X = hstack([X_numeric, X_text])
else:
    X = X_text

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
metrics = {
    "accuracy": accuracy_score(y_test, y_pred),
    "precision": precision_score(y_test, y_pred),
    "recall": recall_score(y_test, y_pred),
    "f1_score": f1_score(y_test, y_pred)
}
logging.info(f"Logistic Regression Metrics: {metrics}")
print("Logistic Regression model trained and saved.")

# Save model
joblib.dump(model, 'src/models/logistic_model.pkl')
joblib.dump(vectorizer, 'src/models/logistic_vectorizer.pkl')