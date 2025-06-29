#!/usr/bin/env python3
"""
Sample vulnerable Python code for testing the security scanner
This file intentionally contains security vulnerabilities for demonstration
"""

import os
import pickle
import subprocess
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# SQL Injection vulnerability
@app.route('/user/<userid>')
def get_user(userid):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE id = {userid}"
    cursor.execute(query)
    return str(cursor.fetchone())

# Command Injection vulnerability
@app.route('/ping')
def ping():
    # VULNERABLE: Direct user input to shell command
    host = request.args.get('host', 'localhost')
    result = os.system(f'ping -c 1 {host}')
    return f"Ping result: {result}"

# Insecure Deserialization
@app.route('/load')
def load_data():
    # VULNERABLE: Unpickling untrusted data
    data = request.args.get('data', '')
    if data:
        obj = pickle.loads(data.encode())
        return f"Loaded: {obj}"
    return "No data"

# Hardcoded credentials
DATABASE_PASSWORD = "admin123"  # VULNERABLE: Hardcoded password
API_KEY = "sk-1234567890abcdef"  # VULNERABLE: Hardcoded API key

# Weak cryptography
def encrypt_password(password):
    # VULNERABLE: Using MD5 for password hashing
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# Path Traversal vulnerability
@app.route('/read_file')
def read_file():
    # VULNERABLE: No path validation
    filename = request.args.get('file', 'readme.txt')
    with open(filename, 'r') as f:
        return f.read()

# XSS vulnerability
@app.route('/greet')
def greet():
    # VULNERABLE: Rendering user input without escaping
    name = request.args.get('name', 'Guest')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    # VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0')