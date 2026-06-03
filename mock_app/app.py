from flask import Flask, request, jsonify
import logging
import time
import random
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)

# Configuration des logs au format Apache
log_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'generated_logs')
os.makedirs(log_dir, exist_ok=True)

log_path = os.path.join(log_dir, 'access.log')

logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(message)s'
)

def write_log(ip, method, endpoint, status, user_agent, response_time):
    now = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')
    line = f'{ip} - - [{now}] "{method} {endpoint} HTTP/1.1" {status} - "{user_agent}"'
    logging.info(line)

# Base de données SQLite ultra-simple
def init_db():
    conn = sqlite3.connect('mock_app/vinted.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users
        (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT)
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS listings
        (id INTEGER PRIMARY KEY, title TEXT, price INTEGER,
         category TEXT, city TEXT, seller_id INTEGER)
    ''')

    # Insérer quelques utilisateurs légitimes
    try:
        c.execute("INSERT INTO users VALUES (1,'amel@gmail.com','pass123')")
        c.execute("INSERT INTO users VALUES (2,'yacine@gmail.com','pass456')")
    except:
        pass

    # Insérer quelques annonces
    sample_listings = [
        (1, "Veste en jean Levi's", 4500, 'women', 'Alger', 1),
        (2, 'Nike Air Force', 6000, 'shoes', 'Oran', 2),
        (3, 'Sac Zara', 2800, 'accessories', 'Alger', 1),
        (4, "Robe d'été", 1500, 'women', 'Constantine', 2),
        (5, 'Jean slim H&M', 2200, 'men', 'Alger', 1),
        (6, 'Chaussures Adidas', 5500, 'shoes', 'Oran', 2),
        (7, 'Manteau hiver', 7000, 'women', 'Alger', 1),
        (8, 'T-shirt vintage', 900, 'men', 'Constantine', 2),
    ]

    try:
        c.executemany("INSERT INTO listings VALUES (?,?,?,?,?,?)", sample_listings)
    except:
        pass

    conn.commit()
    conn.close()

init_db()

# Endpoints

@app.route('/api/auth/login', methods=['POST'])
def login():
    start = time.time()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'unknown')

    data = request.get_json(silent=True) or {}
    email = data.get('email', '')
    password = data.get('password', '')

    conn = sqlite3.connect('mock_app/vinted.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
    user = c.fetchone()
    conn.close()

    rt = int((time.time() - start) * 1000)

    if user:
        write_log(ip, 'POST', '/api/auth/login', 200, ua, rt)
        return jsonify({'status': 'ok', 'token': 'mock_token_xyz'}), 200
    else:
        write_log(ip, 'POST', '/api/auth/login', 401, ua, rt)
        return jsonify({'error': 'Invalid credentials'}), 401

# NOUVEL ENDPOINT - Pour Hydra (form-data au lieu de JSON)
@app.route('/api/auth/login-form', methods=['POST'])
def login_form():
    start = time.time()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'unknown')

    # Récupérer les données du formulaire (pas JSON)
    email = request.form.get('email', '')
    password = request.form.get('password', '')

    conn = sqlite3.connect('mock_app/vinted.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
    user = c.fetchone()
    conn.close()

    rt = int((time.time() - start) * 1000)

    if user:
        write_log(ip, 'POST', '/api/auth/login-form', 200, ua, rt)
        return jsonify({'status': 'ok', 'token': 'mock_token_xyz'}), 200
    else:
        write_log(ip, 'POST', '/api/auth/login-form', 401, ua, rt)
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/register', methods=['POST'])
def register():
    start = time.time()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'unknown')

    data = request.get_json(silent=True) or {}
    email = data.get('email', '')
    password = data.get('password', '')

    conn = sqlite3.connect('mock_app/vinted.db')
    c = conn.cursor()

    try:
        c.execute("INSERT INTO users (email, password) VALUES (?,?)", (email, password))
        conn.commit()
        status = 201
        response = jsonify({'status': 'created'}), 201
    except sqlite3.IntegrityError:
        status = 409
        response = jsonify({'error': 'Email already exists'}), 409

    conn.close()

    rt = int((time.time() - start) * 1000)
    write_log(ip, 'POST', '/api/auth/register', status, ua, rt)

    return response


@app.route('/api/listings', methods=['GET'])
def get_listings():
    start = time.time()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'unknown')

    conn = sqlite3.connect('mock_app/vinted.db')
    c = conn.cursor()
    c.execute("SELECT * FROM listings")
    rows = c.fetchall()
    conn.close()

    listings = [
        {'id': r[0], 'title': r[1], 'price': r[2],
         'category': r[3], 'city': r[4]}
        for r in rows
    ]

    rt = int((time.time() - start) * 1000)
    write_log(ip, 'GET', '/api/listings', 200, ua, rt)

    return jsonify(listings), 200


@app.route('/api/listings/<int:listing_id>', methods=['GET'])
def get_listing(listing_id):
    start = time.time()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'unknown')

    conn = sqlite3.connect('mock_app/vinted.db')
    c = conn.cursor()
    c.execute("SELECT * FROM listings WHERE id=?", (listing_id,))
    row = c.fetchone()
    conn.close()

    rt = int((time.time() - start) * 1000)

    if row:
        write_log(ip, 'GET', f'/api/listings/{listing_id}', 200, ua, rt)
        return jsonify({'id': row[0], 'title': row[1], 'price': row[2]}), 200
    else:
        write_log(ip, 'GET', f'/api/listings/{listing_id}', 404, ua, rt)
        return jsonify({'error': 'Not found'}), 404


@app.route('/api/messages', methods=['POST'])
def send_message():
    start = time.time()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'unknown')

    rt = int((time.time() - start) * 1000)
    write_log(ip, 'POST', '/api/messages', 200, ua, rt)

    return jsonify({'status': 'sent'}), 200


@app.route('/api/orders', methods=['POST'])
def create_order():
    start = time.time()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'unknown')

    rt = int((time.time() - start) * 1000)
    write_log(ip, 'POST', '/api/orders', 201, ua, rt)

    return jsonify({
        'status': 'order_created',
        'order_id': random.randint(1000, 9999)
    }), 201


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'running', 'app': 'Vinted Algeria Mock'}), 200


if __name__ == '__main__':
    print("=== Vinted Algeria Mock App ===")
    print(f"Logs: {log_path}")
    print("Running on http://0.0.0.0:5000")
    print("")
    print("Endpoints disponibles:")
    print("  POST /api/auth/login      - JSON")
    print("  POST /api/auth/login-form - Formulaire (pour Hydra)")
    print("  POST /api/auth/register   - JSON")
    print("  GET  /api/listings")
    print("  GET  /api/listings/<id>")
    print("  POST /api/messages")
    print("  POST /api/orders")
    print("  GET  /api/health")

    app.run(host='0.0.0.0', port=5000, debug=False)