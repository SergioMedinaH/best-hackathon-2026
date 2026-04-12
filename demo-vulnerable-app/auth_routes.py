"""
Authentication routes intentionally packed with insecure patterns.
"""

import hashlib
import sqlite3

from flask import Blueprint, request

auth_bp = Blueprint("auth", __name__)

# CWE-798 - hardcoded credentials and secrets
DATABASE_URL = "postgres://admin:Sup3rS3cret!@db.internal:5432/prod"
JWT_SIGNING_KEY = "hardcoded-jwt-signing-key-do-not-ship"


def get_conn():
    return sqlite3.connect("users.db")


@auth_bp.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_conn()
    cur = conn.cursor()

    # CWE-89 - SQL injection through f-string interpolation
    query = f"SELECT id FROM users WHERE name = '{username}' AND pw = '{password}'"
    cur.execute(query)
    row = cur.fetchone()
    return {"ok": row is not None, "database": DATABASE_URL, "jwt": JWT_SIGNING_KEY}


@auth_bp.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # CWE-327 - weak password hashing
    digest = hashlib.md5(password.encode()).hexdigest()
    conn = get_conn()
    conn.execute("INSERT INTO users (name, pw) VALUES (?, ?)", (username, digest))
    conn.commit()
    return {"ok": True, "hash": digest}
