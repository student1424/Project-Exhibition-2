# app.py
import uuid
from werkzeug.utils import secure_filename
import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
import mailparser

# --- NEW: Define Quarantine Folder ---
QUARANTINE_FOLDER = 'quarantine'
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
# -------------------------------------

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- UPDATED: Load the best trained model (Linear SVC) ---
model_path = "models/email_classifier_Linear_SVC.pkl"
if not os.path.exists(model_path):
    raise FileNotFoundError("Trained model not found! Please run train_model.py first.")
model = joblib.load(model_path)
# ---------------------------------------------------------

app = Flask(__name__, static_folder="static")

# --- NEW: Set a maximum content length for uploads (10 MB) ---
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
# -----------------------------------------------------------

# Home route -> serves index.html
@app.route("/")
def home():
    return send_from_directory("static", "index.html")

# Route for analyzing plain text
@app.route("/analyze_text", methods=["POST"])
def analyze_text():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400
    text = data["text"]
    prediction = model.predict([text])[0]
    return jsonify({"prediction": prediction})

# Route for analyzing uploaded .eml file
@app.route("/analyze_eml", methods=["POST"])
def analyze_eml():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Use a secure version of the filename
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    try:
        mail = mailparser.parse_from_file(filepath)
        text = (mail.subject or "") + " " + (mail.body or "")
        prediction = model.predict([text])[0]
        # Return filename along with prediction for clarity
        return jsonify({"filename": filename, "prediction": prediction})
    except Exception as e:
        return jsonify({"error": f"Failed to parse email: {str(e)}"}), 500

# --- UPDATED ROUTE FOR ATTACHMENT ANALYSIS AND QUARANTINE ---
@app.route("/analyze_attachment", methods=["POST"])
def analyze_attachment():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if file:
        filename = secure_filename(file.filename)
        # Static analysis based on file extension
        suspicious_extensions = ['.html', '.js', '.exe', '.dll', '.bat', '.sh', '.vbs', '.docm', '.xlsm']
        file_ext = os.path.splitext(filename)[1].lower()

        if file_ext in suspicious_extensions:
            # This is a suspicious file, quarantine it
            unique_filename = f"{uuid.uuid4()}-{filename}"
            quarantine_path = os.path.join(QUARANTINE_FOLDER, unique_filename)
            
            # Reset file pointer before saving
            file.seek(0)
            file.save(quarantine_path)

            response = {
                "filename": filename,
                "prediction": "suspicious",
                "status": "quarantined",
                "details": f"Suspicious file extension ({file_ext}) detected. File moved to quarantine."
            }
            return jsonify(response)
        else:
            # This is a safe file, no action needed
            response = {
                "filename": filename,
                "prediction": "safe",
                "details": f"File extension ({file_ext}) is considered safe."
            }
            return jsonify(response)

    return jsonify({"error": "An unknown error occurred"}), 500
# ----------------------------------------------------------------

# Serve CSS/JS from static folder
@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

if __name__ == "__main__":
    app.run(debug=True)

    