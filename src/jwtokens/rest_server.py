import base64
import secrets
import sqlite3
from functools import wraps

from flask import Flask, jsonify, request

from src.jwtokens import criar_token_jwt, verifica_token_jwt

app = Flask(__name__)
DATABASE = 'phone_book.db'
SECRET_KEY = secrets.token_bytes(32)
SECRET_KEY_BASE64 = base64.urlsafe_b64encode(SECRET_KEY).decode('utf-8')


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users;')
    cursor.execute('''
        CREATE TABLE users (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            telephone TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()


def token_required(acao):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            jwt_token = request.headers.get('Authorization')
            if not jwt_token:
                return jsonify({'error': 'Token is missing'}), 403
            try:
                data = verifica_token_jwt(jwt_token, SECRET_KEY)
                if not data.get('valid', False):
                    return jsonify(data), 403
                extra_data = data.get('extra_data')
                if not extra_data:
                    return jsonify(data), 403
                if extra_data.get('role') != 'admin' or data.get('action') != acao:
                    return jsonify({'error': 'Insufficient permissions'}), 403
            except Exception as e:
                return jsonify({'error': str(e)}), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.route('/users', methods=['GET'])
def list_users():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return jsonify([{'email': user[0], 'name': user[1], 'telephone': user[2]} for user in users])


@app.route('/user/<email>', methods=['GET'])
def get_user(email):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({'email': user[0], 'name': user[1], 'telephone': user[2]})
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/user/<email>', methods=['DELETE'])
@token_required('delete')
def delete_user(email):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE email = ?', (email,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User deleted'})


@app.route('/new', methods=['POST'])
@token_required('create')
def create_user():
    data = request.get_json()
    email = data.get('email')
    name = data.get('name')
    telephone = data.get('telephone')
    if not email or not name or not telephone:
        return jsonify({'error': 'Missing data'}), 400
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (email, name, telephone) VALUES (?, ?, ?)',
                       (email, name, telephone))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User already exists'}), 400
    conn.close()
    return jsonify({'message': 'User created'})


@app.route('/user/<email>', methods=['PUT'])
@token_required('update')
def update_user(email):
    data = request.get_json()
    name = data.get('name')
    telephone = data.get('telephone')
    if not name or not telephone:
        return jsonify({'error': 'Missing data'}), 400
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET name = ?, telephone = ? WHERE email = ?',
                   (name, telephone, email))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User updated'})


if __name__ == '__main__':
    init_db()
    print(f"SECRET KEY: {SECRET_KEY} (base64 {SECRET_KEY_BASE64})")
    for action in ['create', 'update', 'delete']:
        token = criar_token_jwt(sub='user@domain.tld',
                                sign_key=SECRET_KEY,
                                action=action,
                                expires_in=600,
                                extra_data={'role': 'admin'})
        print(f"Token de {action}: {token}")
    app.run(debug=False)
