from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

def train_model(texts, labels, vectorizer):
    # Convert raw text into TF-IDF features
    X = vectorizer.fit_transform(texts)
    y = labels

    # Split dataset into training and testing sets
    # 20& for testing, 80% for training
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Train a simple logistic regression model
    model = LogisticRegression()
    model.fit(X_train, y_train)

    # Make predictions on the test set
    predictions = model.predict(X_test)

    # Show detailed evaluation metrics
    print("Classifications Report: ")
    print(classification_report(y_test, predictions))

    # Show confusion matrix to see exactly which emails are misclassified
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    return model, vectorizer