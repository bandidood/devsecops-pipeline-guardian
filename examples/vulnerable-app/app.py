"""
Intentionally Vulnerable Application for Testing Security Scanners
WARNING: This code contains security vulnerabilities for testing purposes only!
DO NOT use in production!
"""

import os
import pickle
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded credentials (Security Issue #1)
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdef"

# SQL Injection vulnerability (Security Issue #2)
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    return str(result)

# XSS vulnerability (Security Issue #3)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable to XSS
    template = f"""
    <html>
        <body>
            <h1>Search Results for: {query}</h1>
        </body>
    </html>
    """
    return render_template_string(template)

# Command Injection vulnerability (Security Issue #4)
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Vulnerable to command injection
    result = os.system(f'ping -c 1 {host}')
    return f"Ping result: {result}"

# Insecure Deserialization (Security Issue #5)
@app.route('/load')
def load_data():
    data = request.args.get('data')
    if data:
        # Vulnerable to insecure deserialization
        obj = pickle.loads(bytes.fromhex(data))
        return str(obj)
    return "No data provided"

# Path Traversal (Security Issue #6)
@app.route('/file')
def read_file():
    filename = request.args.get('name')
    # Vulnerable to path traversal
    with open(f'./files/{filename}', 'r') as f:
        content = f.read()
    return content

# Weak cryptography (Security Issue #7)
import random
def generate_token():
    # Using insecure random number generator
    return random.randint(100000, 999999)

# Debug mode enabled (Security Issue #8)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
