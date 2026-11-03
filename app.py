import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secrets (Caught by TruffleHog & Bandit)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"

@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability (Caught by Bandit & Semgrep)
    query = f"SELECT email, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return str(cursor.fetchall())

@app.route("/calc")
def run_calc():
    expr = request.args.get("expr")
    # Dangerous eval() execution (Caught by Bandit & Semgrep)
    return str(eval(expr))

if __name__ == "__main__":
    app.run(debug=True)