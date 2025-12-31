"""
Intentionally vulnerable Python code for Snyk SAST testing
Contains various security vulnerabilities that Snyk should detect
"""

import os
import pickle
import yaml
import subprocess
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)


# SQL Injection vulnerability
def get_user_by_id(user_id):
    """SQL Injection - direct string concatenation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()


# Command Injection vulnerability
def ping_host(hostname):
    """Command Injection - unsanitized input to shell"""
    command = f"ping -c 1 {hostname}"
    result = subprocess.call(command, shell=True)
    return result


# Path Traversal vulnerability
def read_log_file(filename):
    """Path Traversal - no validation of file path"""
    log_path = f"/var/logs/{filename}"
    with open(log_path, 'r') as f:
        return f.read()


# Deserialization vulnerability
def load_user_data(serialized_data):
    """Insecure Deserialization - pickle is unsafe"""
    user_data = pickle.loads(serialized_data)
    return user_data


# YAML Deserialization vulnerability
def parse_config(yaml_string):
    """YAML Deserialization - unsafe yaml.load"""
    config = yaml.load(yaml_string)
    return config


# Server-Side Template Injection (SSTI)
@app.route('/greet')
def greet():
    """Template Injection - user input in template"""
    name = request.args.get('name', 'Guest')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


# Hardcoded credentials
def connect_to_database():
    """Hardcoded Credentials"""
    db_password = "super_secret_password123"
    db_user = "admin"
    api_key = "sk-1234567890abcdef"
    return f"postgresql://{db_user}:{db_password}@localhost/mydb"


# Weak cryptography
def encrypt_data(data):
    """Weak Cryptography - using MD5"""
    import hashlib
    return hashlib.md5(data.encode()).hexdigest()


# Insecure random
def generate_token():
    """Insecure Random - using random instead of secrets"""
    import random
    return ''.join([str(random.randint(0, 9)) for _ in range(10)])


# XXE vulnerability potential
def parse_xml(xml_string):
    """XML External Entity - unsafe XML parsing"""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_string)
    return root


# Open redirect
@app.route('/redirect')
def redirect_user():
    """Open Redirect - unvalidated redirect"""
    from flask import redirect
    url = request.args.get('url')
    return redirect(url)


# Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    """XSS - unsanitized output"""
    query = request.args.get('q', '')
    return f"<html><body>You searched for: {query}</body></html>"


# Insecure file permissions
def create_sensitive_file():
    """Insecure File Permissions"""
    with open('/tmp/sensitive_data.txt', 'w') as f:
        f.write("Secret information")
    os.chmod('/tmp/sensitive_data.txt', 0o777)


# Use of eval()
def calculate(expression):
    """Code Injection - eval with user input"""
    result = eval(expression)
    return result


# Debug mode enabled
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
