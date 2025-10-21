# vulnerable_app.py
from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

DB_FILE = "vuln.db"

# --- Initialisation base de données ---
def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)")
        cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
        conn.commit()
        conn.close()
        print("Base créée avec utilisateur admin / admin123")

init_db()

# --- Route de login (vulnérable) ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ❌ Vulnérabilité : concaténation directe
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Requête SQL exécutée :", query)

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        try:
            cur.execute(query)
            result = cur.fetchone()
        except Exception as e:
            return f"Erreur SQL : {e}"

        if result:
            return f"<h2>Bienvenue {username} !</h2><p>Connexion réussie.</p>"
        else:
            return "<h3>Identifiants incorrects</h3>"

    return '''
        <h2>Connexion</h2>
        <form method="post">
            Utilisateur: <input name="username"><br>
            Mot de passe: <input type="password" name="password"><br>
            <input type="submit" value="Se connecter">
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
