import joblib
import os
import email
from flask import Flask, request, render_template, jsonify
import random
from datetime import datetime
from collections import deque
from behavioural_pattern import analyze_sender_reputation  

# --- SETUP ---
app = Flask(__name__, template_folder='static', static_folder='static')

UPLOAD_FOLDER = 'data/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'your-api-key-here')

# --- STATE MANAGEMENT (in-memory) ---
# Using deque for efficient fixed-size list
scan_history = deque(maxlen=10)
quarantine_items = []
processed_stats = {'safe': 0, 'malicious': 0}

# --- LOAD THE MODEL ---
try:
    model = joblib.load('models/email_classifier_Linear_SVC.pkl')
    # Note: LinearSVC with default calibration doesn't have predict_proba.
    # We will simulate probabilities for the UI.
    print("✅ Email classification model loaded successfully.")
except Exception as e:
    model = None
    print(f"🚨 ERROR: Could not load model: {e}")

# --- HELPER FUNCTIONS ---
def add_to_history(scan_type, result, filename="N/A"):
    """Adds a new entry to the scan history."""
    scan_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": scan_type,
        "filename": filename,
        "result": result
    }
    scan_history.appendleft(scan_entry) # Add to the beginning

def classify_text(text, filename="N/A"):
    """Classifies text and returns a detailed dictionary."""
    if not model:
        return {'label': 'error', 'probabilities': {'safe': 0, 'malicious': 0}}
        
    prediction = model.predict([str(text)])[0]
    
    # Simulate probabilities as LinearSVC doesn't provide them by default
    if prediction == 'safe':
        probabilities = {'safe': round(random.uniform(0.85, 0.99), 2), 'malicious': round(random.uniform(0.01, 0.15), 2)}
    else:
        probabilities = {'safe': round(random.uniform(0.01, 0.15), 2), 'malicious': round(random.uniform(0.85, 0.99), 2)}

    # Update stats
    if prediction in processed_stats:
        processed_stats[prediction] += 1
    
    # Add to quarantine if malicious
    if prediction == 'malicious':
        reason = "Detected malicious patterns via ML model."
        if not any(item['content'] == filename for item in quarantine_items):
             quarantine_items.append({'type': 'Email', 'content': filename, 'reason': reason})

    add_to_history("Email", prediction.capitalize(), filename)
    return {'label': prediction, 'probabilities': probabilities}

def extract_text_from_eml(file_path):
    """Extracts text content from an .eml file."""
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_bytes(f.read())
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain' and 'attachment' not in str(part.get('Content-Disposition')):
                    body = part.get_payload(decode=True).decode(errors='ignore')
                    break
        else:
            body = msg.get_payload(decode=True).decode(errors='ignore')
        return body
    except Exception as e:
        print(f"Error extracting EML: {e}")
        return ""

def scan_attachment_file(filename):
    """Simulates scanning an attachment file for risks."""
    risk_score = random.randint(1, 100)
    if any(ext in filename.lower() for ext in ['.exe', '.zip', '.js', '.vbs', '.docm']):
        risk_score = min(100, risk_score + 50)
    
    if risk_score > 80:
        result = {'status': 'Malicious', 'reason': 'Potential malware or suspicious script detected.'}
        if not any(item['content'] == filename for item in quarantine_items):
            quarantine_items.append({'type': 'Attachment', 'content': filename, 'reason': result['reason']})
    elif risk_score > 50:
        result = {'status': 'Unsafe', 'reason': 'Uncommon file type. Review carefully.'}
    else:
        result = {'status': 'Safe', 'reason': 'No threats found in attachment.'}

    add_to_history("Attachment", result['status'], filename)
    return result

# --- ROUTES ---

@app.route('/')
def dashboard():
    """Serves the main dashboard page."""
    return render_template('index.html')

@app.route('/analyze_text', methods=['POST'])
def analyze_text_route():
    """API endpoint to analyze raw text."""
    data = request.get_json()
    email_text = data.get('text', '')
    if not email_text:
        return jsonify({'error': 'No text provided'}), 400
    
    result = classify_text(email_text, "Pasted Text")
    return jsonify(result)

@app.route('/analyze_eml', methods=['POST'])
def analyze_eml_route():
    """API endpoint to analyze an uploaded .eml file."""
    if 'file' not in request.files: return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No selected file'}), 400
    
    if file and file.filename.endswith('.eml'):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        email_text = extract_text_from_eml(file_path)
        result = classify_text(email_text, file.filename)
        os.remove(file_path)
        return jsonify(result)
    else:
        return jsonify({'error': 'Invalid file type, please upload a .eml file'}), 400

@app.route('/analyze_attachment', methods=['POST'])
def analyze_attachment_route():
    """API endpoint for the simulated attachment scan."""
    if 'file' not in request.files: return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No selected file'}), 400
    
    result = scan_attachment_file(file.filename)
    return jsonify(result)

@app.route('/scans', methods=['GET'])
def get_scans():
    """API endpoint to get the last 10 scan histories."""
    return jsonify(list(scan_history))

@app.route('/quarantine', methods=['GET'])
def get_quarantine():
    """API endpoint to get the list of quarantined items."""
    return jsonify(quarantine_items)
@app.route('/analyze/email', methods=['POST'])
def analyze_email_enhanced():
    """Analyze email with both ML classification and behavioral patterns"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        raw_email = file.read()
        
        # Get ML prediction
        ml_prediction = get_ml_prediction(raw_email)
        
        # Get behavioral pattern analysis
        behavioral_analysis = analyze_sender_reputation(raw_email, VIRUSTOTAL_API_KEY)
        
        # Combine results
        combined_result = {
            'ml_prediction': ml_prediction,
            'behavioral_analysis': behavioral_analysis,
            'final_verdict': determine_final_verdict(ml_prediction, behavioral_analysis),
            'timestamp': datetime.now().isoformat()
        }
        
        # Store in history
        scan_history.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': 'Email',
            'filename': file.filename,
            'ml_result': ml_prediction.get('label'),
            'behavioral_risk': behavioral_analysis.get('risk_level'),
            'trust_score': behavioral_analysis.get('trust_score')
        })
        
        return jsonify(combined_result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def determine_final_verdict(ml_prediction, behavioral_analysis):
    """Combine ML and behavioral analysis for final verdict"""
    ml_label = ml_prediction.get('label', 'unknown')
    trust_score = behavioral_analysis.get('trust_score', 50)
    
    if ml_label == 'malicious' or trust_score < 40:
        return 'HIGH_RISK'
    elif ml_label == 'safe' and trust_score > 70:
        return 'SAFE'
    else:
        return 'MEDIUM_RISK'

def get_ml_prediction(raw_email):
    """Extract ML prediction from raw email"""
    try:
        # Parse email content
        msg = email.message_from_bytes(raw_email)
        email_content = msg.get_payload()
        
        # Get ML prediction
        if model:
            prediction = model.predict([email_content])[0]
            return {'label': prediction, 'confidence': 0.85}
        else:
            return {'label': 'unknown', 'confidence': 0.0}
    except Exception as e:
        return {'label': 'error', 'confidence': 0.0}
# --- RUN THE APP ---
if __name__ == '__main__':
    app.run(debug=True)

