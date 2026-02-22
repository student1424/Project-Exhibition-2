import pandas as pd
import os
from tqdm import tqdm

# --- Configuration ---
RAW_CSV_PATH = "raw_datasets/emails.csv"
OUTPUT_DIR = "data/ham_txt/"
SAMPLE_SIZE = 5000  # Number of emails to process
# ---------------------

def extract_body(message):
    """
    Extracts the body from a raw email message string.
    The body is assumed to start after the first double newline.
    """
    try:
        # Split the message at the first double newline
        parts = message.split('\n\n', 1)
        if len(parts) == 2:
            return parts[1]
        else:
            # If no double newline, return the whole message as a fallback
            return message
    except Exception:
        return "" # Return empty string on error

def main():
    """
    Main function to load, process, and save the Enron dataset.
    """
    print(f"Loading Enron dataset from {RAW_CSV_PATH}...")
    if not os.path.exists(RAW_CSV_PATH):
        print(f"Error: Dataset not found at {RAW_CSV_PATH}")
        print("Please download the Enron dataset from Kaggle and place emails.csv in the raw_datasets folder.")
        return

    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Load the dataset
    df = pd.read_csv(RAW_CSV_PATH)
    print(f"Dataset loaded with {len(df)} emails.")

    # Take a sample of the dataset
    print(f"Processing a sample of {SAMPLE_SIZE} emails...")
    df_sample = df.head(SAMPLE_SIZE)

    # Use tqdm for a progress bar
    for index, row in tqdm(df_sample.iterrows(), total=df_sample.shape[0], desc="Processing Enron Emails"):
        email_message = row['message']
        
        # Extract the body
        email_body = extract_body(email_message)

        # Basic cleaning: remove extra whitespace
        cleaned_body = ' '.join(email_body.split())

        if cleaned_body:
            # Create a unique filename, padded with zeros for sorting
            filename = f"enron_ham_{index+1:05d}.txt"
            output_path = os.path.join(OUTPUT_DIR, filename)
            
            # Save the cleaned body to a .txt file
            with open(output_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(cleaned_body)

    print(f"\nProcessing complete.")
    print(f"{SAMPLE_SIZE} emails have been processed and saved to the '{OUTPUT_DIR}' directory.")


if __name__ == "__main__":
    main()
    