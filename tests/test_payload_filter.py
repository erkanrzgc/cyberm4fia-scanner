from utils.payload_filter import PayloadFilter

def test_payload_filter_os():
    payloads = [
        "../../../etc/passwd",
        "/bin/bash -c id",
        "C:\\windows\\system.ini",
        "..\\..\\windows\\system32\\cmd.exe",
        "echo 123", # Generic
    ]
    
    # Target is Linux
    filtered = PayloadFilter.filter_payloads(payloads, {"os": "linux"})
    assert "C:\\windows\\system.ini" not in filtered
    assert "..\\..\\windows\\system32\\cmd.exe" not in filtered
    assert "../../../etc/passwd" in filtered
    assert "/bin/bash -c id" in filtered
    assert "echo 123" in filtered # Generic should pass

    # Target is Windows
    filtered = PayloadFilter.filter_payloads(payloads, {"os": "windows"})
    assert "../../../etc/passwd" not in filtered
    assert "/bin/bash -c id" not in filtered
    assert "C:\\windows\\system.ini" in filtered
    assert "..\\..\\windows\\system32\\cmd.exe" in filtered
    assert "echo 123" in filtered # Generic should pass

def test_payload_filter_db():
    payloads = [
        "1' AND SLEEP(5)--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND pg_sleep(5)--",
        "1' OR 1=1--" # Generic
    ]
    
    # Target is MySQL
    filtered = PayloadFilter.filter_payloads(payloads, {"db": "mysql"})
    assert "1' AND SLEEP(5)--" in filtered
    assert "1' WAITFOR DELAY '0:0:5'--" not in filtered
    assert "1' AND pg_sleep(5)--" not in filtered
    assert "1' OR 1=1--" in filtered
    
    # Target is MSSQL
    filtered = PayloadFilter.filter_payloads(payloads, {"db": "mssql"})
    assert "1' AND SLEEP(5)--" not in filtered
    assert "1' WAITFOR DELAY '0:0:5'--" in filtered
    assert "1' AND pg_sleep(5)--" not in filtered
    assert "1' OR 1=1--" in filtered

def test_payload_filter_lang():
    payloads = [
        "php://filter/convert.base64-encode/resource=index.php",
        "{{7*7}}", # Generic SSTI
        "${T(java.lang.Runtime).getRuntime().exec('id')}", 
        "{{''.__class__.__mro__[2].__subclasses__()}}"
    ]
    
    # Target is Python
    filtered = PayloadFilter.filter_payloads(payloads, {"lang": "python"})
    assert "php://filter/convert.base64-encode/resource=index.php" not in filtered
    assert "${T(java.lang.Runtime).getRuntime().exec('id')}" not in filtered
    assert "{{''.__class__.__mro__[2].__subclasses__()}}" in filtered
    assert "{{7*7}}" in filtered

def test_payload_filter_no_context():
    payloads = ["../../../etc/passwd", "C:\\windows\\system.ini"]
    # No context or empty context should not filter anything
    assert len(PayloadFilter.filter_payloads(payloads, None)) == 2
    assert len(PayloadFilter.filter_payloads(payloads, {})) == 2
    assert len(PayloadFilter.filter_payloads(payloads, {"os": "unknown"})) == 2
