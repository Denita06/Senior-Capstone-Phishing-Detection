from src.email_ingest.dataset_loader import load_dataset
from src.feature_extraction.vectorizer import create_vectorizer
from src.model.train import train_model

def main():
    base_path = "data/raw"

    print("Loading dataset...")
    texts, labels = load_dataset(base_path)

    print("Creating vectorizer...")
    vectorizer = create_vectorizer()

    print("Training model...")
    model, vectorizer = train_model(texts, labels, vectorizer)

    print("MVP Complete.")

if __name__ == "__main__":
    main()