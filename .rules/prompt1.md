Create a quick single-file Python prototype called `app.py` and a `requirements.txt` file for local testing:
1. In `requirements.txt`, pin `Flask==2.0.1`, `requests==2.19.0`, and `pyyaml==5.3.1`.
2. In `app.py`, hardcode a test AWS Secret Key variable (`AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`) and a GitHub Token (`GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"`).
3. Create a function `get_user(username)` that connects to `users.db` via `sqlite3` and uses a raw Python f-string `SELECT email, role FROM users WHERE username = '{username}'` to look up a user.
4. Create a function `run_calc(expression)` that uses Python's `eval(expression)` to calculate math input from a user.