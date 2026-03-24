import pytest
import ftplib
import socket
from unittest.mock import MagicMock, patch
from modules.brute_force import BruteForcer

@pytest.fixture
def bruter():
    return BruteForcer(timeout=1, max_attempts=5)

@patch("ftplib.FTP")
def test_brute_ftp_success(mock_ftp, bruter):
    # Setup mock to fail first two times, succeed on third
    instance = mock_ftp.return_value
    instance.login.side_effect = [
        ftplib.error_perm("530 Login incorrect"),
        ftplib.error_perm("530 Login incorrect"),
        None # Success
    ]
    
    # We will test 3 pairs
    creds = [("admin", "admin"), ("root", "root"), ("test", "test")]
    results = bruter.brute_ftp("127.0.0.1", creds=creds)
    
    assert len(results) == 1
    assert results[0]["username"] == "test"
    assert results[0]["password"] == "test"
    assert instance.login.call_count == 3

@patch("ftplib.FTP")
def test_brute_ftp_timeout(mock_ftp, bruter):
    instance = mock_ftp.return_value
    instance.connect.side_effect = socket.timeout("timed out")
    
    creds = [("admin", "admin")]
    results = bruter.brute_ftp("127.0.0.1", creds=creds)
    
    # Should abort and return empty list
    assert len(results) == 0

@patch("paramiko.SSHClient")
def test_brute_ssh_success(mock_ssh, bruter):
    instance = mock_ssh.return_value
    
    import paramiko
    instance.connect.side_effect = [
        paramiko.AuthenticationException("Failed"),
        None # Success
    ]
    
    # We will test 2 pairs
    creds = [("admin", "admin"), ("root", "root")]
    results = bruter.brute_ssh("127.0.0.1", creds=creds)
    
    assert len(results) == 1
    assert results[0]["username"] == "root"

def test_results_to_findings(bruter):
    results = [
        {"service": "ssh", "host": "10.0.0.1", "port": 22, "username": "root", "password": "123", "evidence": "root@kali"}
    ]
    findings = bruter.results_to_findings(results)
    
    assert len(findings) == 1
    assert findings[0]["type"] == "Default_Credentials"
    assert findings[0]["severity"] == "critical"
    assert "root:123" in findings[0]["payload"]
