# tests/test_urls.py
import pytest
from utils.url_reputation import is_malicious_url, extract_urls

@pytest.fixture
def mock_db():
    """A mock PhishTank database for testing."""
    return {"http://test.phishing.com/login", "https://another.bad.site/verify"}

def test_is_malicious_url_positive(mock_db):
    """Test a URL that is in the database."""
    assert is_malicious_url("http://test.phishing.com/login", mock_db) is True

def test_is_malicious_url_negative(mock_db):
    """Test a URL that is not in the database."""
    assert is_malicious_url("https://www.google.com", mock_db) is False

def test_extract_urls():
    """Test URL extraction from a block of text."""
    text = "Please visit http://safe.com and also check out https://insecure.net/page.html for more info."
    urls = extract_urls(text)
    assert len(urls) == 2
    assert "http://safe.com" in urls
    assert "https://insecure.net/page.html" in urls