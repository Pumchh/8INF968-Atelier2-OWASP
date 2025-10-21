# app.py
from flask import Flask, request, redirect, url_for, session, render_template_string, g, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

DATABASE = 'users.db'
SECRET_KEY = os.urandom(24)

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# --- Templates (simple inline templates to éviter la création de fichiers) ---
TPL_LOGIN = """
<!doctype html>
<title>Login</title>
<h2>Connexion</h2>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul style="color:red;">
    {% for m in messages %}<li>{{ m }}</li>{% endfor %}
    </ul>
  {% endif %}
{% endwith %}
<form method="post">
  <label>Utilisateur: <input name="username"></label><br>
  <label>Mot de passe: <input type="password" name="password"></label><br>
  <button type="submit">Se connecter</button>
</form>
"""

TPL_ADMIN = """
<!doctype html>
<title>Admin</title>
<h2>Page Admin</h2>
<p>Bonjour, {{ user }} !</p>
<p>Liste des utilisateurs :</p>
<ul>
{% for u in users %}
  <li>{{ u }}</li>
{% endfor %}
</ul>
<a href="{{ url_for('logout') }}">Se déconnecter</a>
"""

# --- DB helpers ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0
    );
    """)
    db.commit()

def ensure_admin():
    db = get_db()
    cur = db.execute("SELECT username FROM users WHERE is_admin = 1 LIMIT 1")
    row = cur.fetchone()
    if not row:
        # Create default admin (username: admin, password: admin123) -> hashed
        username = "admin"
        password = "admin123"
        password_hash = generate_password_hash(password)
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                (username, password_hash)
            )
            db.commit()
            print("Admin créé: username='admin', password='admin123' (change it!)")
        except sqlite3.IntegrityError:
            pass

# --- Routes ---
@app.before_first_request
def setup():
    init_db()
    ensure_admin()

@app.route('/', methods=['GET'])
def index():
    if session.get('username'):
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Veuillez renseigner tous les champs.")
            return render_template_string(TPL_LOGIN)

        db = get_db()
        # Requête PARAMÉTRÉE — protège contre les injections SQL
        cur = db.execute("SELECT username, password_hash, is_admin FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            return redirect(url_for('admin'))
        else:
            flash("Identifiants incorrects.")
            return render_template_string(TPL_LOGIN)
    else:
        return render_template_string(TPL_LOGIN)

@app.route('/admin')
def admin():
    if not session.get('username'):
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        return "Accès refusé", 403

    db = get_db()
    cur = db.execute("SELECT username FROM users ORDER BY id")
    users = [r['username'] for r in cur.fetchall()]
    return render_template_string(TPL_ADMIN, user=session['username'], users=users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Ajout d'un utilisateur (exemple sécurisé) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Endpoint minimal pour montrer l'ajout d'utilisateur, protégé par requêtes paramétrées
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Tous les champs sont requis.")
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)",
                (username, generate_password_hash(password))
            )
            db.commit()
            flash("Utilisateur créé. Connectez-vous.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Nom d'utilisateur déjà utilisé.")
            return redirect(url_for('register'))
    return """
    <!doctype html>
    <h2>Créer un compte</h2>
    <form method="post">
      <label>Utilisateur: <input name="username"></label><br>
      <label>Mot de passe: <input type="password" name="password"></label><br>
      <button type="submit">Créer</button>
    </form>
    """

if __name__ == '__main__':
    # Mode debug pour développement local uniquement
    app.run(debug=True)
