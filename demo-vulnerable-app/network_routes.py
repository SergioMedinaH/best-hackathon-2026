"""
Network-facing routes intentionally trust unvalidated user input.
"""

import subprocess

import requests
from flask import Blueprint, request

network_bp = Blueprint("network", __name__)


@network_bp.route("/ping")
def ping():
    host = request.args.get("host", "localhost")

    # CWE-78 - command injection
    output = subprocess.check_output(f"ping -n 1 {host}", shell=True)
    return output


@network_bp.route("/fetch")
def fetch_url():
    url = request.args.get("url")

    # CWE-918 - SSRF
    response = requests.get(url, timeout=5)
    return response.text
