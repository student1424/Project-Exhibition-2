import pandas as pd
import os
from tqdm import tqdm

# --- Configuration ---
RAW_CSV_PATH = "raw_datasets/phishing_email.csv"
OUTPUT_HAM_DIR = "data/ham_txt/"
OUTPUT_PHISH_DIR = "data/phish_txt/"
# ---------------------

def main():
    """
    Main function to load, process, and save the Kaggle Phishing dataset.
    """
    print(f"Loading Kaggle Phishing dataset from {RAW_CSV_PATH}...")
    if not os.path.exists(RAW_CSV_PATH):
        print(f"Error: Dataset not found at {RAW_CSV_PATH}")
        return

    os.makedirs(OUTPUT_HAM_DIR, exist_ok=True)
    os.makedirs(OUTPUT_PHISH_DIR, exist_ok=True)

    df = pd.read_csv(RAW_CSV_PATH)
    print(f"Dataset loaded with {len(df)} emails.")
    
    # FIX: Use the correct column names found in your file
    df.dropna(subset=['text_combined', 'label'], inplace=True)

    ham_counter = 0
    phish_counter = 0

    for index, row in tqdm(df.iterrows(), total=df.shape[0], desc="Processing Kaggle Emails"):
        # FIX: Use the correct column names here
        email_text = row['text_combined']
        label = row['label'] # This column likely contains 0 for safe, 1 for phishing

        cleaned_text = ' '.join(str(email_text).split())

        if cleaned_text:
            # FIX: Check for integer labels 0 and 1
            if label == 0: # Safe Email
                ham_counter += 1
                filename = f"kphish_safe_{ham_counter:04d}.txt"
                output_path = os.path.join(OUTPUT_HAM_DIR, filename)
            elif label == 1: # Phishing Email
                phish_counter += 1
                filename = f"kphish_malicious_{phish_counter:04d}.txt"
                output_path = os.path.join(OUTPUT_PHISH_DIR, filename)
            else:
                continue 

            with open(output_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(cleaned_text)

    print("\nProcessing complete.")
    print(f"{ham_counter} safe emails saved to '{OUTPUT_HAM_DIR}'")
    print(f"{phish_counter} malicious emails saved to '{OUTPUT_PHISH_DIR}'")

if __name__ == "__main__":
    main()
    