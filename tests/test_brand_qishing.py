import pytest
from unittest.mock import patch, MagicMock

from utils.brand_protection import generate_typosquatting_domains, check_phishing_domains
from utils.qishing import extract_qr_from_image, analyze_image_for_qishing

# --- Brand Protection Tests ---

def test_generate_typosquatting_domains():
    domains = generate_typosquatting_domains("google.com")
    assert isinstance(domains, list)
    assert len(domains) > 0
    # Omission
    assert "gogle.com" in domains
    # Repetition
    assert "gooogle.com" in domains
    # TLD
    assert "google.net" in domains
    
def test_generate_typosquatting_invalid():
    assert generate_typosquatting_domains("localhost") == []
    assert generate_typosquatting_domains("") == []

@patch("socket.gethostbyname")
def test_check_phishing_domains_found(mock_gethostbyname):
    # Mock DNS resolutions
    def mock_dns(domain):
        if domain == "example.com":
            return "1.1.1.1" # Target IP
        if domain == "examp1e.com":
            return "2.2.2.2" # Phishing IP
        if domain == "example.net":
            return "1.1.1.1" # Same owner, same IP, safe
        raise Exception("socket.gaierror") # Domain not registered
        
    mock_gethostbyname.side_effect = mock_dns
    
    with patch("utils.brand_protection.generate_typosquatting_domains") as mock_generate:
        # Force it to return the exact domain we're mocking
        mock_generate.return_value = ["examp1e.com", "example.net"]
        findings = check_phishing_domains("https://example.com")
    
    assert len(findings) == 1
    assert findings[0]["type"] == "Brand_Protection_Phishing"
    assert findings[0]["severity"] == "HIGH"
    assert "examp1e.com" in findings[0]["evidence"]

@patch("socket.gethostbyname")
def test_check_phishing_domains_unreachable_target(mock_gethostbyname):
    mock_gethostbyname.side_effect = Exception("socket.gaierror")
    findings = check_phishing_domains("https://unknown-target.com")
    assert len(findings) == 0


# --- Qishing Tests ---

@pytest.mark.skipif(
    not __import__("utils.qishing", fromlist=["QR_MODULES_AVAILABLE"]).QR_MODULES_AVAILABLE,
    reason="pyzbar/pillow not installed — qishing test requires QR modules",
)
@patch("utils.qishing.QR_MODULES_AVAILABLE", True)
@patch("utils.qishing.Image.open")
@patch("utils.qishing.decode")
def test_analyze_image_qishing_vulnerable(mock_decode, mock_open):
    # Mock image opening
    mock_open.return_value = MagicMock()
    
    # Mock pyzbar decode returning an external URL
    mock_obj = MagicMock()
    mock_obj.type = "QRCODE"
    mock_obj.data = b"https://evil-phishing-site.com/login"
    mock_decode.return_value = [mock_obj]
    
    findings = analyze_image_for_qishing("https://example.com/qr.png", b"fake_bytes", "example.com")
    
    assert len(findings) == 1
    assert findings[0]["type"] == "Qishing_Vulnerability"
    assert findings[0]["severity"] == "HIGH"
    assert "evil-phishing-site.com" in findings[0]["description"]

@pytest.mark.skipif(
    not __import__("utils.qishing", fromlist=["QR_MODULES_AVAILABLE"]).QR_MODULES_AVAILABLE,
    reason="pyzbar/pillow not installed — qishing test requires QR modules",
)
@patch("utils.qishing.QR_MODULES_AVAILABLE", True)
@patch("utils.qishing.Image.open")
@patch("utils.qishing.decode")
def test_analyze_image_qishing_safe(mock_decode, mock_open):
    # Mock image opening
    mock_open.return_value = MagicMock()
    
    # Mock pyzbar decode returning an internal URL
    mock_obj = MagicMock()
    mock_obj.type = "QRCODE"
    mock_obj.data = b"https://example.com/safe-link"
    mock_decode.return_value = [mock_obj]
    
    findings = analyze_image_for_qishing("https://example.com/qr.png", b"fake_bytes", "example.com")
    
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["variant"] == "Internal QR Code (Safe)"
