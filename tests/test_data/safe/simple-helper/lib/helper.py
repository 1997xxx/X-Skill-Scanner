#!/usr/bin/env python3
"""
Simple Helper Skill - Safe Sample
This is a safe skill for scanner validation.
"""

def greet(name):
    """Greet the user"""
    return f"Hello, {name}!"

def calculate(a, b, operation="add"):
    """Perform simple calculations"""
    if operation == "add":
        return a + b
    elif operation == "subtract":
        return a - b
    elif operation == "multiply":
        return a * b
    elif operation == "divide":
        return a / b if b != 0 else None
    else:
        return None

def format_text(text, style="normal"):
    """Format text in different styles"""
    if style == "upper":
        return text.upper()
    elif style == "lower":
        return text.lower()
    elif style == "title":
        return text.title()
    else:
        return text

# Safe configuration reading
def load_config(config_path):
    """Load configuration from a file"""
    import json
    from pathlib import Path

    config_file = Path(config_path)
    if not config_file.exists():
        return {}

    with open(config_file, 'r') as f:
        return json.load(f)

# Safe HTTP request
def fetch_data(url):
    """Fetch data from a URL"""
    import requests

    # Only allow HTTPS
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS URLs are allowed")

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    return response.json()