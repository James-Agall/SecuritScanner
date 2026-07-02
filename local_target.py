from flask import Flask, request
import sqlite3
import os
import subprocess
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

def generate_self_signed_cert(cert_path='cert.pem', key_path='key.pem'):
    """Generates a self-signed cert/key pair for local HTTPS testing, if they don't already exist."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Test Target"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
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

def init_user_db():
    db_path = 'users.db'
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT
            )
        ''')
        cursor.execute("INSERT INTO users (id, username) VALUES (1, 'admin')")
        conn.commit()
        conn.close()

@app.route('/')
def index():
    # Added links so the crawler can discover the vulnerable pages
    return """
    <h1>Welcome to the local target</h1>
    <ul>
        <li><a href='/user?id=1'>Go to User 1</a></li>
        <li><a href='/transfer'>Transfer Money</a></li>
        <li><a href='/ping'>Ping a Host</a></li>
    </ul>
    """

@app.route('/search')
def search():
    query = request.args.get('query')
    return f"<h1>Search results for: {query}</h1>"

@app.route('/user')
def user():
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
def env_file():
    return "DB_PASSWORD=SuperSecret123\nAPI_KEY=sk-12345"

# Simulate an exposed admin panel
@app.route('/admin')
def admin_panel():
    return "<h1>Admin Dashboard</h1><p>Welcome, Administrator.</p>"

# Vulnerable form without CSRF token
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
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
def ping():
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