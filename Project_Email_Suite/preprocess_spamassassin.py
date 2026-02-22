import os
import email
from tqdm import tqdm
from email.parser import BytesParser


# --- Configuration ---
# UPDATED: Paths to the new extracted spam and ham folders
RAW_SPAM_DIR = "raw_datasets/spam_2/"
RAW_HAM_DIR = "raw_datasets/easy_ham_2/"

# Output directories
OUTPUT_SPAM_DIR = "data/phish_txt/"
OUTPUT_HAM_DIR = "data/ham_txt/"
# ---------------------

def get_email_body(raw_email):
    """
    Parses a raw email string to extract its body.
    """
    try:
        msg = BytesParser().parsebytes(raw_email.encode())
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    return part.get_payload(decode=True).decode(errors='ignore')
        else:
            return msg.get_payload(decode=True).decode(errors='ignore')
    except Exception:
        return ""

def process_directory(input_dir, output_dir, prefix, desc):
    """
    Processes all email files in an input directory and saves them.
    """
    if not os.path.isdir(input_dir):
        print(f"Warning: Directory not found, skipping: {input_dir}")
        return 0

    os.makedirs(output_dir, exist_ok=True)
    
    email_files = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    
    file_counter = 0
    for file_path in tqdm(email_files, desc=desc):
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                raw_email = f.read()

            email_body = get_email_body(raw_email)
            cleaned_body = ' '.join(email_body.split())

            if cleaned_body:
                file_counter += 1
                filename = f"{prefix}_{file_counter:04d}.txt"
                output_path = os.path.join(output_dir, filename)
                
                with open(output_path, 'w', encoding='utf-8') as out_f:
                    out_f.write(cleaned_body)
        except Exception as e:
            print(f"Skipping file {file_path} due to error: {e}")
            
    return file_counter

def main():
    """
    Main function to process both spam and ham directories.
    """
    print("Processing SpamAssassin corpus...")
    
    spam_count = process_directory(RAW_SPAM_DIR, OUTPUT_SPAM_DIR, "sa_spam", "Processing Spam")
    ham_count = process_directory(RAW_HAM_DIR, OUTPUT_HAM_DIR, "sa_ham", "Processing Ham")

    print("\nProcessing complete.")
    print(f"{spam_count} spam emails saved to '{OUTPUT_SPAM_DIR}'")
    print(f"{ham_count} ham emails saved to '{OUTPUT_HAM_DIR}'")

if __name__ == "__main__":
    main()
    