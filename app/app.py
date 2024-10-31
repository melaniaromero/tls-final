from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask import send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import base64
from flask_socketio import SocketIO, send
import hashlib
import hmac

app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.config['SECRET_KEY'] = 'supersecretkey'
socketio = SocketIO(app)

# Simulación de base de datos
users = {}

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
            return 'Llave privada subida correctamente'
    return render_template('upload_key.html')

@app.route('/generate_keys')
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Cifrar la llave privada
    cipher = AES.new(b'secretpassword12', AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    encrypted_private_key = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    # Guardar las llaves en archivos
    with open('private.pem', 'wb') as f:
        f.write(private_key)
    with open('public.pem', 'wb') as f:
        f.write(public_key)

    return send_file('private.pem', as_attachment=True)



@socketio.on('message')
def handleMessage(msg):
    # Aquí puedes añadir el hash y la firma digital
    hashed_msg = hashlib.sha256(msg.encode()).hexdigest()
    signature = hmac.new(b'secretkey', msg.encode(), hashlib.sha256).hexdigest()
    send({'msg': msg, 'hash': hashed_msg, 'signature': signature}, broadcast=True)



if __name__ == '__main__':
    app.run(debug=True)
    socketio.run(app, debug=True)
