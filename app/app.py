# Importamos las bibliotecas necesarias para construir la aplicación web y las funcionalidades de seguridad.
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

# Inicializamos la aplicación Flask y configuramos la clave secreta para sesiones.
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SECRET_KEY'] = 'supersecretkey'  # Configuración adicional para Flask-SocketIO
socketio = SocketIO(app)  # Inicializamos SocketIO para permitir comunicación en tiempo real.

# Simulación de una base de datos en memoria para almacenar usuarios y usuarios conectados.
users = {}
connected_users = []

# Ruta de inicio para la página principal.
@app.route('/')
def home():
    return render_template('home.html')  # Renderiza la página principal.

# Ruta para iniciar sesión.
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # Si el método es POST, intentamos autenticar al usuario.
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)  # Obtenemos los datos del usuario de la "base de datos".
        if user and check_password_hash(user['password'], password):  # Verificamos la contraseña.
            session['username'] = username  # Guardamos el nombre de usuario en la sesión.
            session['password'] = password  # Guardamos la contraseña en la sesión para la derivación de clave.
            return redirect(url_for('dashboard'))  # Redirige al usuario al tablero si la autenticación es exitosa.
        else:
            return 'Nombre de usuario o contraseña incorrectos'
    return render_template('login.html')  # Renderiza el formulario de inicio de sesión si el método es GET.

# Ruta para el registro de nuevos usuarios.
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':  # Si el método es POST, procesamos el registro.
        username = request.form['username']
        password = request.form['password']
        if username in users:  # Verificamos si el usuario ya existe.
            return 'El usuario ya existe'
        users[username] = {'password': generate_password_hash(password)}  # Guardamos el hash de la contraseña.
        return redirect(url_for('login'))  # Redirige al formulario de inicio de sesión tras el registro.
    return render_template('register.html')  # Renderiza el formulario de registro si el método es GET.

# Ruta para el tablero del usuario autenticado.
@app.route('/dashboard')
def dashboard():
    if 'username' in session:  # Verifica si el usuario está autenticado.
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))  # Redirige a inicio de sesión si el usuario no está autenticado.

# Ruta para cargar una clave privada.
@app.route('/upload_key', methods=['GET', 'POST'])
def upload_key():
    if request.method == 'POST':
        file = request.files['file']  # Recibe el archivo de clave privada cargado por el usuario.
        if file:
            private_key = file.read()  # Lee el contenido del archivo.
            # Aquí puedes guardar la llave privada de forma segura (no implementado en este ejemplo).
            return redirect(url_for('chat'))  # Redirige al chat después de cargar la clave.
    return render_template('upload_key.html')  # Renderiza el formulario de carga de clave si el método es GET.

# Ruta para generar y descargar claves asimétricas (pública y privada).
@app.route('/generate_keys')
def generate_keys():
    key = RSA.generate(2048)  # Genera un par de claves RSA de 2048 bits.
    private_key = key.export_key()  # Exporta la clave privada en formato binario.
    public_key = key.publickey().export_key()  # Exporta la clave pública en formato binario.
    
    # Cifra la clave privada con AES usando una clave derivada de la contraseña del usuario.
    password = session.get('password')  # Recupera la contraseña del usuario.
    salt = os.urandom(16)  # Genera un salt aleatorio.
    key_derivation = PBKDF2(password, salt, dkLen=32)  # Deriva una clave simétrica con PBKDF2.
    cipher = AES.new(key_derivation, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    encrypted_private_key = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')  # Codifica en base64.

    # Guarda las claves en archivos locales.
    private_key_path = os.path.join(os.getcwd(), 'private.pem')
    with open(private_key_path, 'wb') as f:
        f.write(encrypted_private_key.encode('utf-8'))
    with open(os.path.join(os.getcwd(), 'public.pem'), 'wb') as f:
        f.write(public_key)
    
    return send_file(private_key_path, as_attachment=True)  # Permite descargar la clave privada.

# Ruta para el chat en tiempo real.
@app.route('/chat')
def chat():
    if 'username' in session:  # Verifica si el usuario está autenticado.
        return render_template('chat.html', username=session['username'], users=connected_users)
    return redirect(url_for('login'))  # Redirige a inicio de sesión si el usuario no está autenticado.

# Evento de conexión al chat con SocketIO.
@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username and username not in connected_users:  # Agrega el usuario a la lista de conectados.
        connected_users.append(username)
        emit('user_connected', {'username': username}, broadcast=True)  # Notifica a otros usuarios.

        # Envía la lista de usuarios conectados al nuevo usuario.
        emit('update_user_list', {'users': list(connected_users)})

# Evento de desconexión del chat.
@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username in connected_users:  # Elimina el usuario de la lista de conectados.
        connected_users.remove(username)
        emit('user_disconnected', {'username': username}, broadcast=True)  # Notifica a otros usuarios.

# Evento de mensaje en el chat.
@socketio.on('message')
def handleMessage(msg):
    password = session.get('password')  # Recupera la contraseña del usuario para la clave simétrica.
    usuario = session.get('username')
    salt = b'salt_'  # Define un salt (debería ser único y seguro en un entorno real).
    key = PBKDF2(password, salt, dkLen=32)  # Deriva una clave simétrica con PBKDF2.
    cipher = AES.new(key, AES.MODE_EAX)  # Crea un objeto de cifrado AES en modo EAX.
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())  # Cifra el mensaje y genera un tag de autenticación.
    encrypted_msg = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')  # Codifica en base64.

    # Firma digital del mensaje usando RSA.
    private_key_path = os.path.join(os.getcwd(), 'private.pem')
    private_key = RSA.import_key(open(private_key_path).read())  # Importa la clave privada.
    hashed_msg = SHA256.new(encrypted_msg.encode())  # Calcula el hash SHA-256 del mensaje cifrado.
    signature = pkcs1_15.new(private_key).sign(hashed_msg)  # Firma el hash usando PKCS#1 v1.5.
    signature_b64 = base64.b64encode(signature).decode('utf-8')  # Codifica la firma en base64.

    # Envía el mensaje cifrado, su hash y la firma a todos los usuarios conectados.
    send({'username': usuario, 'msg': msg, 'encrypted_msg': encrypted_msg, 'hash': hashed_msg.hexdigest(), 'signature': signature_b64}, broadcast=True)

# Inicia la aplicación Flask y SocketIO en modo debug.
if __name__ == '__main__':
    socketio.run(app, debug=True)
