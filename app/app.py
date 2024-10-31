from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
from flask_socketio import SocketIO, send, emit
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SECRET_KEY'] = 'supersecretkey'
socketio = SocketIO(app)

# Simulación de base de datos
users = {}
connected_users = []

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['password'] = password  # Guardar la contraseña en la sesión para derivar la clave
            return redirect(url_for('dashboard'))
        else:
            return 'Nombre de usuario o contraseña incorrectos'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return 'El usuario ya existe'
        users[username] = {'password': generate_password_hash(password)}
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/upload_key', methods=['GET', 'POST'])
def upload_key():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            private_key = file.read()
            # Aquí puedes guardar la llave privada de forma segura
            return redirect(url_for('chat'))
    return render_template('upload_key.html')

@app.route('/generate_keys')
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    # Cifrar la llave privada con AES
    cipher = AES.new(b'secretpassword12', AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    encrypted_private_key = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    # Guardar las llaves en archivos
    private_key_path = os.path.join(os.getcwd(), 'private.pem')
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    with open(os.path.join(os.getcwd(), 'public.pem'), 'wb') as f:
        f.write(public_key)
    return send_file(private_key_path, as_attachment=True)

@app.route('/chat')
def chat():
    if 'username' in session:
        return render_template('chat.html', username=session['username'], users=connected_users)
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username and username not in connected_users:
        connected_users.append(username)
        emit('user_connected', {'username': username}, broadcast=True)

        # Envía la lista completa de usuarios conectados al nuevo usuario
        emit('update_user_list', {'users': list(connected_users)})

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username in connected_users:
        connected_users.remove(username)
        emit('user_disconnected', {'username': username}, broadcast=True)

@socketio.on('message')
def handleMessage(msg):
    password = session.get('password')
    usuario = session.get('username')
    salt = b'salt_'  # Puedes generar un salt aleatorio y guardarlo
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    encrypted_msg = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    # Crear firma digital
    private_key_path = os.path.join(os.getcwd(), 'private.pem')
    private_key = RSA.import_key(open(private_key_path).read())
    hashed_msg = SHA256.new(encrypted_msg.encode())
    signature = pkcs1_15.new(private_key).sign(hashed_msg)
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    send({'username': usuario, 'msg': msg, 'encrypted_msg': encrypted_msg, 'hash': hashed_msg.hexdigest(), 'signature': signature_b64}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
