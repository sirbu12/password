from flask import Flask, request, jsonify, session, send_from_directory
from dotenv import load_dotenv
import os
import sqlite3
import bcrypt
import time

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
LOCK_TIME = os.getenv("LOCK_TIME")
MAX_ATTEMPTS = os.getenv("MAX_ATTEMPTS")

if not SECRET_KEY:
    raise RuntimeError("SECURITY ERROR: SECRET_KEY missing in .env")

if not LOCK_TIME:
    raise RuntimeError("CONFIG ERROR: LOCK_TIME missing in .env")

if not MAX_ATTEMPTS:
    raise RuntimeError("CONFIG ERROR: MAX_ATTEMPTS missing in .env")

LOCK_TIME = int(LOCK_TIME)
MAX_ATTEMPTS = int(MAX_ATTEMPTS)

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "backend", "database.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lock_until REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_attempts (
                ip TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lock_until REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.commit()


init_db()

def check_ip_rate_limit(conn, ip):
    now = time.time()
    cursor = conn.execute("SELECT failed_attempts, lock_until FROM ip_attempts WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    if row:
        if float(row["lock_until"]) > now:
            return False
    return True

def record_ip_failure(conn, ip):
    now = time.time()
    cursor = conn.execute("SELECT failed_attempts, lock_until FROM ip_attempts WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    if row:
        failed = int(row["failed_attempts"]) + 1
        lock_until = float(row["lock_until"])
        if failed >= MAX_ATTEMPTS:
            lock_until = now + LOCK_TIME
            failed = 0
        conn.execute("UPDATE ip_attempts SET failed_attempts = ?, lock_until = ? WHERE ip = ?", (failed, lock_until, ip))
    else:
        conn.execute("INSERT INTO ip_attempts (ip, failed_attempts, lock_until) VALUES (?, 1, 0)", (ip,))

def record_ip_success(conn, ip):
    conn.execute("UPDATE ip_attempts SET failed_attempts = 0, lock_until = 0 WHERE ip = ?", (ip,))


def valid_password(pw):
    if len(pw) < 8:
        return False
    if pw.isalpha() or pw.isdigit():
        return False
    return True

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response

@app.route("/api/register", methods=["POST"])
def register():
    ip = request.remote_addr
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    password2 = data.get("password2") or ""

    if not username or not password:
        return jsonify({"error": "missing fields"}), 400

    if password != password2:
        return jsonify({"error": "password mismatch"}), 400

    if not valid_password(password):
        return jsonify({"error": "weak password"}), 400

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        with get_db_connection() as conn:
            if not check_ip_rate_limit(conn, ip):
                return jsonify({"error": "ip locked, try later"}), 403

            cursor = conn.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone() is not None:
                record_ip_failure(conn, ip)
                conn.commit()
                return jsonify({"error": "user exists"}), 400

            conn.execute(
                """
                INSERT INTO users (username, password, failed_attempts, lock_until)
                VALUES (?, ?, 0, 0)
                """,
                (username, hashed),
            )
            conn.commit()
    except sqlite3.Error:
        return jsonify({"error": "database error"}), 500

    return jsonify({"message": "account created, now log in"})

@app.route("/api/login", methods=["POST"])
def login():
    ip = request.remote_addr
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "invalid credentials"}), 401

    try:
        with get_db_connection() as conn:
            if not check_ip_rate_limit(conn, ip):
                return jsonify({"error": "ip locked, try later"}), 403

            cursor = conn.execute(
                """
                SELECT username, password, failed_attempts, lock_until
                FROM users
                WHERE username = ?
                """,
                (username,),
            )
            user = cursor.fetchone()

            if user is None:
                # DUMMY BCRYPT HASH CHECK to prevent timing attacks
                # Use a valid but arbitrary bcrypt hash
                dummy_hash = b"$2b$12$L7R/y4K81Yh6M2rT4F6EBeU8h5g1kY12tO/M2W5H1j8P9hZ7s3W/K"
                bcrypt.checkpw(password.encode("utf-8"), dummy_hash)
                record_ip_failure(conn, ip)
                conn.commit()
                return jsonify({"error": "invalid credentials"}), 401

            now = time.time()

            # LOCK CHECK
            if float(user["lock_until"]) > now:
                return jsonify({"error": "account locked, try later"}), 403

            stored_hash = user["password"]

            # PASSWORD CHECK
            if not bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
                record_ip_failure(conn, ip)

                failed_attempts = int(user["failed_attempts"]) + 1
                lock_until = float(user["lock_until"])

                if failed_attempts >= MAX_ATTEMPTS:
                    lock_until = now + LOCK_TIME
                    failed_attempts = 0

                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts = ?, lock_until = ?
                    WHERE username = ?
                    """,
                    (failed_attempts, lock_until, username),
                )
                conn.commit()

                return jsonify({"error": "invalid credentials"}), 401

            # SUCCESS RESET
            record_ip_success(conn, ip)
            conn.execute(
                """
                UPDATE users
                SET failed_attempts = 0, lock_until = 0
                WHERE username = ?
                """,
                (username,),
            )
            conn.commit()

    except sqlite3.Error:
        return jsonify({"error": "database error"}), 500

    session["user"] = username
    return jsonify({"message": "voila", "user": username})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"message": "logged out"})

@app.route("/api/me")
def me():
    return jsonify({"user": session.get("user")})

if __name__ == "__main__":
    app.run(debug=False)