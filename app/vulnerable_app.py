"""
Intentionally insecure Flask demo for SAST/DAST education.

This module is meant to trigger Bandit rules such as B307 (eval), B105
(hard-coded secrets), and B602 (subprocess with shell=True). Do not deploy
or expose to the internet.
"""

from __future__ import annotations

import subprocess

from flask import Flask, request

app = Flask(__name__)

# Bandit B105: possible hardcoded password string (demo only).
DEMO_ADMIN_PASSWORD = "insecure_static_password"


@app.route("/")
def index() -> str:
    """Simple landing page so ZAP and health checks have a stable URL."""
    return (
        "<h1>SDLC demo app</h1>"
        "<p>This app exists only to exercise security scanners in CI.</p>"
        "<ul>"
        '<li><a href="/evaluate?code=1%2B1">/evaluate</a> (unsafe)</li>'
        '<li><a href="/ping?host=127.0.0.1">/ping</a> (unsafe)</li>'
        "<li>POST /login with form field password</li>"
        "</ul>"
    )


@app.route("/evaluate")
def evaluate() -> str:
    """
    UNSAFE: evaluates user-controlled input with eval().
    Bandit typically flags this as B307 (blacklist: eval).
    """
    code = request.args.get("code", "1+1")
    # Explicitly unsafe: never do this in production.
    result = eval(code)
    return str(result)


@app.route("/login", methods=["GET", "POST"])
def login() -> str | tuple[str, int]:
    """
    UNSAFE: compares against a hard-coded password (weak auth pattern).
    """
    if request.method == "GET":
        return (
            '<form method="post">'
            'Password: <input name="password" type="password" />'
            '<button type="submit">Login</button>'
            "</form>"
        )

    password = request.form.get("password", "")
    if password == DEMO_ADMIN_PASSWORD:
        return "logged_in"
    return ("denied", 401)


@app.route("/ping")
def ping() -> str:
    """
    UNSAFE: passes user input to a shell command.
    Bandit flags subprocess with shell=True (B602).
    """
    host = request.args.get("host", "127.0.0.1")
    # Linux-friendly ping; CI runners are Linux. Still unsafe with shell=True.
    subprocess.run(f"ping -c 1 {host}", shell=True, check=False)
    return "ok"


if __name__ == "__main__":
    # Running directly is for local dev only; CI uses `flask run`.
    app.run(host="0.0.0.0", port=5000, debug=False)
