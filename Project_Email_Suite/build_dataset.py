import pandas as pd
import os
import random
from tqdm import tqdm

# --- Configuration ---
HAM_DIR = "data/ham_txt/"
PHISH_DIR = "data/phish_txt/"
OUTPUT_CSV = "data/dataset.csv"
TARGET_SAMPLES = 5000 # The number of samples per class
# ---------------------

def read_files_from_dir(directory, label, max_samples, pbar_desc):
    """Reads text files from a directory and assigns a label."""
    data = []
    filenames = os.listdir(directory)
    random.shuffle(filenames) # Shuffle for random sampling

    files_to_process = filenames[:max_samples]

    print(f"Reading {len(files_to_process)} files from {directory}...")
    for filename in tqdm(files_to_process, desc=pbar_desc):
        file_path = os.path.join(directory, filename)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
                data.append({'text': text, 'label': label})
        except Exception as e:
            print(f"Could not read file {filename}: {e}")

    return data

def main():
    """Combines ham and phish text files into a single balanced CSV."""
    ham_data = read_files_from_dir(HAM_DIR, 'safe', TARGET_SAMPLES, "Reading Safe Emails")
    phish_data = read_files_from_dir(PHISH_DIR, 'malicious', TARGET_SAMPLES, "Reading Malicious Emails")

    all_data = ham_data + phish_data
    df = pd.DataFrame(all_data)
    df = df.sample(frac=1).reset_index(drop=True)

    print(f"\nFinal dataset has {len(df)} total samples.")
    print(f"Saving balanced dataset to {OUTPUT_CSV}...")
    df.to_csv(OUTPUT_CSV, index=False)
    print("Dataset build complete.")

if __name__ == "__main__":
    main()
    