from unittest.mock import patch
from core.interactive import interactive_menu

def test_interactive_menu_all_in_one_flow():
    def mock_input(prompt, default=""):
        p = prompt.lower()
        if "resume session file" in p or "session file" in p:
            return ""
        if "target url" in p:
            return "http://test.local"
        if "choice [1]" in p:
            return "1" # Mode
        if "choice [4]" in p:
            return "4" # Profile All-in-One
        if "wordlist" in p:
            return "n"
        if "start scan" in p:
            return "Y"
        if "json_output" in p or "json" in p:
            return "n"
        return default

    with patch("core.interactive.get_input", side_effect=mock_input):
        url, mode, delay, final_options = interactive_menu()
        assert url == "http://test.local"
        assert final_options["xss"] is True
        assert final_options["sqli"] is True
        assert final_options["tech"] is True

def test_interactive_menu_custom_choices_flow():
    def mock_input(prompt, default=""):
        p = prompt.lower()
        if "resume session file" in p or "session file" in p:
            return ""
        if "target url" in p:
            return "http://test.local"
        if "choice [1]" in p:
            return "1" # Mode
        if "choice [4]" in p:
            return "5" # Profile Custom
        if "test xss" in p:
            return "y"
        if "test sqli" in p:
            return "y"
        if "start scan" in p:
            return "Y"
        if "json" in p:
            return "n"
        return "n"
        
    with patch("core.interactive.get_input", side_effect=mock_input):
        url, mode, delay, final_options = interactive_menu()
        assert url == "http://test.local"
        assert final_options["xss"] is True
        assert final_options["sqli"] is True
        assert final_options["lfi"] is False

def test_interactive_menu_stealth_mode_change():
    def mock_input(prompt, default=""):
        p = prompt.lower()
        if "resume session file" in p or "session file" in p:
            return ""
        if "target url" in p:
            return "http://stealth.local"
        if "choice [1]" in p:
            return "2" # Mode Stealth
        if "choice [4]" in p:
            return "1" # Fast Recon
        if "start scan" in p:
            return "Y"
        if "json" in p:
            return "n"
        return "n"
    
    with patch("core.interactive.get_input", side_effect=mock_input):
        url, mode, delay, final_options = interactive_menu()
        assert url == "http://stealth.local"
        assert mode == "stealth"
        assert final_options["recon"] is True
