import os

# Get project root (go up from src/config/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Define all paths in ONE place
RAW_DATA_PATH = os.path.join(BASE_DIR, "src", "data", "raw")
PROCESSED_DATA_PATH = os.path.join(BASE_DIR, "src", "data", "processed")
LOG_PATH = os.path.join(BASE_DIR, "logs", "errors.log")