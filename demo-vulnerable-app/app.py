"""
Intentionally vulnerable Flask application — for demoing the Security Agent
JetBrains plugin during the BEST UC3M hackathon.

DO NOT DEPLOY. DO NOT EXPOSE TO THE INTERNET.

Each route below contains one (or more) curated vulnerabilities that the
plugin should detect, explain and fix automatically. Vulnerabilities are
labelled with the CWE / OWASP id they map to so the demo narrative is
unambiguous when judges look at the source.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request, send_file

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CWE-798 — Hardcoded credentials
# OWASP A07:2021 Identification & Authentication Failures
# ---------------------------------------------------------------------------
DATABASE_URL = "postgres://admin:Sup3rS3cret!@db.internal:5432/prod"
SECRET_API_KEY = "sk-prod-1234567890abcdef1234567890abcdef"
JWT_SIGNING_KEY = "hardcoded-jwt-signing-key-do-not-ship"


def get_conn():
    return sqlite3.connect("users.db")


# ---------------------------------------------------------------------------
# CWE-89 — SQL Injection (string interpolation in raw query)
# OWASP A03:2021 Injection
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_conn()
    cur = conn.cursor()
    query = f"SELECT id FROM users WHERE name = '{username}' AND pw = '{password}'"
    cur.execute(query)
    row = cur.fetchone()
    return {"ok": row is not None}


# ---------------------------------------------------------------------------
# CWE-78 — OS Command Injection (shell=True with user input)
# OWASP A03:2021 Injection
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    output = subprocess.check_output(f"ping -n 1 {host}", shell=True)
    return output


# ---------------------------------------------------------------------------
# CWE-502 — Insecure Deserialization (pickle.loads on user-controlled bytes)
# OWASP A08:2021 Software & Data Integrity Failures
# ---------------------------------------------------------------------------
@app.route("/restore", methods=["POST"])
def restore_session():
    blob = request.get_data()
    state = pickle.loads(blob)
    return {"restored": str(state)}


# ---------------------------------------------------------------------------
# CWE-502 (variant) — yaml.load without SafeLoader
# ---------------------------------------------------------------------------
@app.route("/config", methods=["POST"])
def upload_config():
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
    return {"loaded": list(cfg.keys()) if isinstance(cfg, dict) else []}


# ---------------------------------------------------------------------------
# CWE-22 — Path Traversal (no sanitisation of filename)
# OWASP A01:2021 Broken Access Control
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join("/var/app/uploads", filename)
    return send_file(path)


# ---------------------------------------------------------------------------
# CWE-918 — Server-Side Request Forgery (URL fetched directly from input)
# OWASP A10:2021 SSRF
# ---------------------------------------------------------------------------
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return resp.text


# ---------------------------------------------------------------------------
# CWE-327 — Use of broken cryptographic algorithm (MD5 for passwords)
# OWASP A02:2021 Cryptographic Failures
# ---------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    digest = hashlib.md5(password.encode()).hexdigest()
    conn = get_conn()
    conn.execute(
        "INSERT INTO users (name, pw) VALUES (?, ?)", (username, digest)
    )
    conn.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# CWE-79 — Server-side Cross-Site Scripting via render_template_string
# OWASP A03:2021 Injection
# ---------------------------------------------------------------------------
@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string(f"<h1>Hello {name}</h1>")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)


