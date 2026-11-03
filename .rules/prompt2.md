# Security & Coding Guardrails for Project

## 1. Secret Hygiene
- Never hardcode API keys, passwords, database credentials, or tokens in source code.
- Always load sensitive configurations using environment variables (`os.environ.get()`).

## 2. Input Validation & Database Security
- Never construct raw SQL queries using f-strings or string concatenation.
- Always use parameterized queries and safe placeholders (e.g., sqlite3 `?` parameters or ORM bindings) to prevent SQL injection.

## 3. Dangerous Function Restrictions
- Never use Python's `eval()` or `exec()` with unsanitized or user-supplied input.
- Avoid insecure deserialization libraries (`pickle`) where safe alternatives exist.

## 4. Environment & Debugging
- Never run production web servers (such as Flask or FastAPI) with `debug=True`.
- Ensure all third-party dependencies added to requirements.txt use patched, secure versions.