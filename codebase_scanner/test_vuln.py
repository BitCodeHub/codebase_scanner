
# Test vulnerable code
import os
import pickle

# Hardcoded secrets
API_KEY = "sk-proj-abc123xyz789"
DATABASE_PASSWORD = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# SQL injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Unsafe deserialization
def load_data(data):
    return pickle.loads(data)

# Weak crypto
import hashlib
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
