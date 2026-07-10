import datetime
import os
import sqlite3
import subprocess

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, Response, jsonify, redirect, request, session, url_for
from flask.typing import ResponseReturnValue
from lxml import etree

app = Flask(__name__)
app.secret_key = "local-dev-only-not-a-real-secret"

# Hardcoded test accounts for the authenticated/IDOR scanning phase
USERS = {
    "admin": "admin123",
    "user1": "user123",
}

def generate_self_signed_cert(cert_path: str = 'cert.pem', key_path: str = 'key.pem') -> None:
    """Generates a self-signed cert/key pair for local HTTPS testing, if they don't already exist."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Test Target"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

def init_user_db() -> None:
    db_path = 'users.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (id, username) VALUES (1, 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username) VALUES (2, 'user1')")
    conn.commit()
    conn.close()

@app.route('/')
def index() -> str:
    # Added links so the crawler can discover the vulnerable pages
    return """
    <h1>Welcome to the local target</h1>
    <ul>
        <li><a href='/user?id=1'>Go to User 1</a></li>
        <li><a href='/transfer'>Transfer Money</a></li>
        <li><a href='/ping'>Ping a Host</a></li>
        <li><a href='/login'>Login</a></li>
        <li><a href="/view-doc?filename=welcome.txt">View Welcome Document</a></li>
        <li><a href="/fetch-data?url=https://example.com">Fetch External Data</a></li>
        <li><a href="/api/user-data">User Data API</a></li>
        <li><a href="/redirect?next=/dashboard">Go to Dashboard</a></li>
    </ul>
    <form method="POST" action="/parse-xml">
        <label>Submit XML:</label><br>
        <textarea name="xml_data" rows="4" cols="50">&lt;data&gt;Hello&lt;/data&gt;</textarea><br>
        <button type="submit">Parse XML</button>
    </form>
    """

# Vulnerable to Open Redirect: the target URL is passed straight to
# redirect() with no allow-list check for internal vs. external hosts.
@app.route('/redirect')
def open_redirect() -> ResponseReturnValue:
    target = request.args.get('url') or request.args.get('next')
    if not target:
        return "Missing 'url' or 'next' parameter"
    return redirect(target)

# Vulnerable to XML External Entity (XXE) Injection: the parser resolves
# external entities, so a DOCTYPE with a SYSTEM entity can read local files.
@app.route('/parse-xml', methods=['POST'])
def parse_xml() -> str:
    try:
        parser = etree.XMLParser(resolve_entities=True)
        root = etree.fromstring(request.data, parser=parser)
        return root.text or ""
    except Exception as e:
        return str(e)

# Vulnerable to CORS Misconfiguration: reflects any Origin back with
# credentials allowed, letting any website read this authenticated data.
@app.route('/api/user-data')
def api_user_data() -> Response:
    response = jsonify({"username": "admin", "email": "admin@example.com"})
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# Vulnerable to Server-Side Request Forgery: the url parameter is fetched
# server-side with no allow-list, so it can be pointed at internal hosts.
@app.route('/fetch-data')
def fetch_data() -> str:
    import urllib3
    urllib3.disable_warnings()

    target_url = request.args.get('url')
    try:
        response = requests.get(target_url, verify=False, timeout=10)  # type: ignore[arg-type]
        return response.text
    except Exception as e:
        return str(e)

# Vulnerable to Path Traversal / Local File Inclusion: the filename parameter
# is passed straight to open() with no allow-list or path sanitization.
@app.route('/view-doc')
def view_doc() -> str:
    filename = request.args.get('filename')
    try:
        with open(filename) as f:  # type: ignore[arg-type]
            return f.read()
    except Exception as e:
        return str(e)

@app.route('/login', methods=['GET', 'POST'])
def login() -> ResponseReturnValue:
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if USERS.get(username) == password:  # type: ignore[arg-type]
            session['logged_in'] = True
            session['username'] = username
            # VULNERABLE: session cookie set with no Secure/HttpOnly/SameSite protection
            response = redirect(url_for('profile', user_id=1))
            response.set_cookie('session_id', 'super_secret_session_token_123', httponly=False, secure=False, samesite='None')
            return response
        return "Invalid credentials"
    return """
    <h1>Login</h1>
    <form method="POST" action="/login">
        <label>Username:</label>
        <input type="text" name="username">
        <br>
        <label>Password:</label>
        <input type="password" name="password">
        <br>
        <button type="submit">Login</button>
    </form>
    """

# Vulnerable to IDOR: any logged-in user can view any other user's profile
# by simply changing the user_id parameter, since there's no ownership check.
@app.route('/profile')
def profile() -> str:
    if not session.get('logged_in'):
        return "Access Denied"

    user_id = request.args.get('user_id')
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return f"<h1>Profile</h1><p>Username: {result[0]}</p>"
        else:
            return "User not found"
    except Exception as e:
        return str(e)

@app.route('/search')
def search() -> str:
    query = request.args.get('query')
    return f"<h1>Search results for: {query}</h1>"

@app.route('/user')
def user() -> str:
    user_id = request.args.get('id')
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # VULNERABLE: Raw string interpolation in SQL query
        query = f"SELECT username FROM users WHERE id = {user_id}"
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return "User not found"
    except Exception as e:
        # VULNERABLE: Returning raw database errors to the user
        return str(e)

# Simulate an exposed .env file containing secrets
@app.route('/.env')
def env_file() -> str:
    return "DB_PASSWORD=SuperSecret123\nAPI_KEY=sk-12345"

# Simulate an exposed admin panel
@app.route('/admin')
def admin_panel() -> str:
    return "<h1>Admin Dashboard</h1><p>Welcome, Administrator.</p>"

# Vulnerable form without CSRF token
@app.route('/transfer', methods=['GET', 'POST'])
def transfer() -> str:
    if request.method == 'POST':
        amount = request.form.get('amount')
        return f"<h1>Transferred ${amount}</h1>"
    return """
    <h1>Transfer Money</h1>
    <form method="POST" action="/transfer">
        <label>Amount: $</label>
        <input type="number" name="amount" value="100">
        <button type="submit">Transfer</button>
    </form>
    """

# Vulnerable to OS Command Injection via unsanitized shell interpolation
@app.route('/ping', methods=['GET', 'POST'])
def ping() -> str:
    if request.method == 'POST':
        target = request.form.get('target')
        # VULNERABLE: User input passed directly to the shell
        result = subprocess.run(f"ping -n 2 {target}", shell=True, capture_output=True, text=True)
        return f"<h1>Ping Results</h1><pre>{result.stdout}</pre>"
    return """
    <h1>Ping a Host</h1>
    <form method="POST" action="/ping">
        <label>IP Address or Hostname:</label>
        <input type="text" name="target" value="127.0.0.1">
        <button type="submit">Ping</button>
    </form>
    """

if __name__ == '__main__':
    init_user_db()
    generate_self_signed_cert()
    app.run(port=5000, ssl_context=('cert.pem', 'key.pem'))