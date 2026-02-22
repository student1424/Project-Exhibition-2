# tests/test_models.py
import pytest
import joblib
import os

# Paths to the new model files
NB_MODEL_PATH = "models/email_classifier_Naive_Bayes.pkl"
SVM_MODEL_PATH = "models/email_classifier_Linear_SVC.pkl"

def test_model_files_exist():
    """Check if both model files have been created."""
    assert os.path.exists(NB_MODEL_PATH), "Naive Bayes model file is missing."
    assert os.path.exists(SVM_MODEL_PATH), "Linear SVC model file is missing."

@pytest.fixture(scope="module")
def models():
    """Load models once for all tests in this module."""
    nb_model = joblib.load(NB_MODEL_PATH)
    svm_model = joblib.load(SVM_MODEL_PATH)
    return {"NB": nb_model, "SVM": svm_model}

def test_models_predict_safe(models):
    """Test that models predict safe text correctly."""
    safe_text = ["Hi team, confirming our meeting for tomorrow. Thanks"]
    for name, model in models.items():
        prediction = model.predict(safe_text)[0]
        assert prediction == "safe", f"{name} model failed on safe text."

def test_models_predict_malicious(models):
    """Test that models predict malicious text correctly."""
    phish_text = ["URGENT action required your bank account is suspended click here"]
    for name, model in models.items():
        prediction = model.predict(phish_text)[0]
        assert prediction == "malicious", f"{name} model failed on malicious text."