import json
import os

DB_FILE = "storage/history.json"


def load_history():
    if not os.path.exists(DB_FILE):
        return {}

    try:
        with open(DB_FILE, "r") as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

        return {}

    except:
        return {}


def save_history(data):
    os.makedirs("storage", exist_ok=True)

    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)
