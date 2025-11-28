# app.py
from flask import Flask, request, render_template_string, g, redirect, url_for, flash
import sqlite3
import logging
import re

DATABASE = "test.db"

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # для flash-повідомлень

# Логування атак
logging.basicConfig(filename="attacks.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

SUSPECT_PATTERNS = [
    r"'\s*or\s*'1'='1", r"or\s+1=1", r"--", r";", r"'\s*--", r"UNION\s+SELECT", r"'\s*OR\s*", r"'\s*;.*DROP"
]
suspect_re = re.compile("|".join(SUSPECT_PATTERNS), re.IGNORECASE)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def log_if_suspect(endpoint, input_str):
    if input_str and suspect_re.search(input_str):
        logging.info("Suspect payload on %s: %s", endpoint, input_str)

# Простий шаблон з формою
BASE = """
<!doctype html>
<title>SQLi Demo</title>
<h1>SQL Injection demo — {{title}}</h1>
<nav>
  <a href="/">Home</a> |
  <a href="/search_vuln">Search (Vulnerable)</a> |
  <a href="/search_safe">Search (Safe)</a> |
  <a href="/login_vuln">Login (Vulnerable)</a> |
  <a href="/login_safe">Login (Safe)</a>
</nav>
<hr>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for m in messages %}
      <li>{{ m }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
{{body}}
<hr>
<p><em>Run locally. Check attacks.log for recorded suspicious inputs.</em></p>
"""

# ---- Vulnerable search: пряме підставлення в SQL (небезпечний приклад) ----
@app.route("/search_vuln", methods=["GET", "POST"])
def search_vuln():
    body = """
    <form method="post">
      Category: <input name="category"> <input type="submit" value="Search (vuln)">
    </form>
    """
    results = None
    if request.method == "POST":
        category = request.form.get("category", "")
        log_if_suspect("search_vuln", category)

        db = get_db()
        # НЕБЕЗПЕЧНО: пряма конкатенація рядка в SQL
        query = "SELECT id, name, category, released FROM products WHERE category = '{}' AND released = 1;".format(category)
        app.logger.debug("VULN QUERY: %s", query)
        try:
            cur = db.execute(query)
            results = cur.fetchall()
        except Exception as e:
            results = [("ERROR", str(e))]
    body += "<h3>Results:</h3>"
    if results:
        body += "<ul>"
        for r in results:
            body += f"<li>{dict(r)}</li>"
        body += "</ul>"
    return render_template_string(BASE, title="Search (Vulnerable)", body=body)

# ---- Safe search: параметризований запит ----
@app.route("/search_safe", methods=["GET", "POST"])
def search_safe():
    body = """
    <form method="post">
      Category: <input name="category"> <input type="submit" value="Search (safe)">
    </form>
    """
    results = None
    if request.method == "POST":
        category = request.form.get("category", "")
        log_if_suspect("search_safe", category)

        db = get_db()
        # БЕЗПЕЧНО: параметри замість конкатенації
        try:
            cur = db.execute("SELECT id, name, category, released FROM products WHERE category = ? AND released = ?;", (category, 1))
            results = cur.fetchall()
        except Exception as e:
            results = [("ERROR", str(e))]
    body += "<h3>Results:</h3>"
    if results:
        body += "<ul>"
        for r in results:
            body += f"<li>{dict(r)}</li>"
        body += "</ul>"
    return render_template_string(BASE, title="Search (Safe)", body=body)

# ---- Vulnerable login: пряме підставлення (небезпечна аутентифікація) ----
@app.route("/login_vuln", methods=["GET", "POST"])
def login_vuln():
    body = """
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Login (vuln)">
    </form>
    """
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        log_if_suspect("login_vuln", username + "||" + password)

        db = get_db()
        # НЕБЕЗПЕЧНО: пряма конкатенація
        q = "SELECT id, username FROM users WHERE username = '{}' AND password = '{}';".format(username, password)
        app.logger.debug("VULN LOGIN QUERY: %s", q)
        try:
            cur = db.execute(q)
            user = cur.fetchone()
        except Exception as e:
            user = None
            flash("Error: " + str(e))
        if user:
            flash("Logged in (vulnerable) as: " + user["username"])
        else:
            flash("Login failed (vulnerable)")
        return redirect(url_for("login_vuln"))
    return render_template_string(BASE, title="Login (Vulnerable)", body=body)

# ---- Safe login: parameterized ----
@app.route("/login_safe", methods=["GET", "POST"])
def login_safe():
    body = """
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Login (safe)">
    </form>
    """
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        log_if_suspect("login_safe", username + "||" + password)

        db = get_db()
        # БЕЗПЕЧНО: параметризований запит
        cur = db.execute("SELECT id, username FROM users WHERE username = ? AND password = ?;", (username, password))
        user = cur.fetchone()
        if user:
            flash("Logged in (safe) as: " + user["username"])
        else:
            flash("Login failed (safe)")
        return redirect(url_for("login_safe"))
    return render_template_string(BASE, title="Login (Safe)", body=body)

@app.route("/")
def index():
    body = """
    <p>Цей додаток має вразливі та захищені маршрути. Спробуйте ввести наступні payload'и у <strong>vulnerable</strong> версіях і спостерігайте:</p>
    <ul>
      <li>Для <em>Search</em>: <code>Gifts' OR '1'='1</code> або <code>Gifts' OR '1'='1' --</code></li>
      <li>Для <em>Login</em>: <code>admin' --</code> у полі username і будь-який пароль</li>
    </ul>
    <p>Потім перевірте ті ж вводи у <strong>safe</strong> версіях — вони не повинні працювати.</p>
    """
    return render_template_string(BASE, title="Home", body=body)

if __name__ == "__main__":
    app.run(debug=True)
