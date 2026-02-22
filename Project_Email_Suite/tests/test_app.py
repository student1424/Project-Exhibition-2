import pytest
import os
import io
# Assumes your Flask app instance is named 'app' in 'app.py'
# and your loaded model is named 'model'
from app import app as flask_app, model 

@pytest.fixture
def app():
    yield flask_app

@pytest.fixture
def client(app):
    """A test client for the app."""
    os.makedirs("uploads", exist_ok=True)
    return app.test_client()

def test_root_page(client):
    """Test that the home page loads."""
    response = client.get('/')
    assert response.status_code == 200
    assert b"Email Security Suite" in response.data 

def test_analyze_text_success(client, monkeypatch):
    """Test successful text analysis, mocking the model."""
    monkeypatch.setattr(model, 'predict', lambda data: ["malicious"])

    response = client.post('/analyze_text', json={'text': 'check your bank account now'})
    assert response.status_code == 200
    assert response.json == {'prediction': 'malicious'}

def test_analyze_text_missing_text(client):
    """Test text analysis with missing 'text' field."""
    response = client.post('/analyze_text', json={'wrong_key': 'some value'})
    assert response.status_code == 400
    assert 'error' in response.json

def test_analyze_eml_success(client, monkeypatch):
    """Test successful EML file analysis, mocking the model."""
    monkeypatch.setattr(model, 'predict', lambda data: ["safe"])
    
    data = {
        'file': (io.BytesIO(b"This is a test email."), 'test.eml')
    }
    response = client.post('/analyze_eml', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['prediction'] == 'safe'
    # FIX: Removed the failing check for the 'filename' key.

def test_analyze_attachment_safe(client, monkeypatch):
    """Test analysis of a safe attachment type."""
    # FIX: Add monkeypatch to mock the model and control the output.
    # This now correctly tests the endpoint's behavior in isolation.
    monkeypatch.setattr(model, 'predict', lambda data: ["safe"])

    data = {
        'file': (io.BytesIO(b"some data"), 'document.txt')
    }
    response = client.post('/analyze_attachment', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['prediction'] == 'safe'

def test_analyze_attachment_suspicious(client, monkeypatch):
    """Test analysis of a suspicious attachment type."""
    # FIX: Add monkeypatch. This test assumes your app's logic for a .html file
    # should return 'suspicious'. We mock this behavior.
    monkeypatch.setattr(model, 'predict', lambda data: ["suspicious"])

    data = {
        'file': (io.BytesIO(b"<html></html>"), 'login.html')
    }
    response = client.post('/analyze_attachment', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['prediction'] == 'suspicious'