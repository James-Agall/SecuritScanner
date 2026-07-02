from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

def init_user_db():
    db_path = 'users.db'
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT
            )
        ''')
        cursor.execute("INSERT INTO users (id, username) VALUES (1, 'admin')")
        conn.commit()
        conn.close()

@app.route('/')
def index():
    # Added a link so the crawler can discover the vulnerable page
    return "<h1>Welcome to the local target</h1><br><a href='/user?id=1'>Go to User 1</a>"

@app.route('/search')
def search():
    query = request.args.get('query')
    return f"<h1>Search results for: {query}</h1>"

@app.route('/user')
def user():
    user_id = request.args.get('id')
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # VULNERABLE: Raw string interpolation in SQL query
        query = f"SELECT username FROM users WHERE id = {user_id}"
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return "User not found"
    except Exception as e:
        # VULNERABLE: Returning raw database errors to the user
        return str(e)

if __name__ == '__main__':
    init_user_db()
    app.run(port=5000)