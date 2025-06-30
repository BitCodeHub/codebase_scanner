import os
import sqlite3
import pickle

# SQL Injection vulnerability
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection
    return conn.execute(query).fetchall()

# Hardcoded password
DB_PASSWORD = "admin123"  # Hardcoded credential
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key

# Command injection
def run_command(user_input):
    os.system(f"echo {user_input}")  # Command injection

# Insecure deserialization
def load_data(data):
    return pickle.loads(data)  # CWE-502: Insecure deserialization