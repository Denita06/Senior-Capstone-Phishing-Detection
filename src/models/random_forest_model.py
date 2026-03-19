import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
import joblib
import logging
import os

logging.basicConfig(filename='logs/model_training.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

csv_path = 'data/processed/emails.csv'
if not os.path.exists(csv_path):
    raise FileNotFoundError(f"{csv_path} not found.")

df = pd.read_csv(csv_path)
y = df['label']

# Text features
vectorizer = TfidfVectorizer(max_features=1000)
X_text = vectorizer.fit_transform(df['content'])

# Numeric features
numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
numeric_cols = [c for c in numeric_cols if c != 'label']
X_numeric = df[numeric_cols].values if numeric_cols else None

# Combine
X = hstack([X_numeric, X_text]) if X_numeric is not None else X_text

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
metrics = {
    "accuracy": accuracy_score(y_test, y_pred),
    "precision": precision_score(y_test, y_pred),
    "recall": recall_score(y_test, y_pred),
    "f1_score": f1_score(y_test, y_pred)
}
logging.info(f"Random Forest Metrics: {metrics}")
print("Random Forest model trained and saved.")

joblib.dump(model, 'src/models/random_forest_model.pkl')
joblib.dump(vectorizer, 'src/models/random_forest_vectorizer.pkl')