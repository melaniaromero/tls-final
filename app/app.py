# Se usa Flask para crear la aplicación web
# Werkzeug para funciones de seguridad como el manejo de contraseñas
# La librería Crypto proporciona métodos de cifrado, firma y manejo de claves
# SocketIO permite comunicación en tiempo real
# hashlib y hmac se usan para crear hash y firmas HMAC
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
import hmac
# Crea una instancia de Flask llamada app 
# Establece una clave secreta para la sesión
# Configura SocketIO para manejar conexiones en tiempo real
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SECRET_KEY'] = 'supersecretkey'
socketio = SocketIO(app)

# Simula una base de datos en memoria con dos diccionarios: 
# users almacena usuarios registrados y connected_users para usuarios conectados.
users = {}
connected_users = {}

#Define la ruta principal (/) y muestra la página de inicio home.html.
# Recordemos que da Bienvenida y da la opción de registrar o iniciar sesión
@app.route('/')
def home():
    return render_template('home.html')

#Maneja el inicio de sesión en /login. 
#Si hay POST, verifica las credenciales y almacena el usuario y la contraseña en la sesión. 
#Si no está registrado regresa un aviso de que está incorrecto.
# Si no, muestra el formulario login.html.

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

#Define la ruta de registro en register. 
# Si el usuario envía POST, se verifica si el usuario ya existe. 
# Si no, se guarda la contraseña hasheada en users y redirige a la página de inicio de sesión(login)
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

#Muestra la página dashboard.html si el usuario está autenticado
# i no, redirige a login.
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

#Aquí se permite al usuario subir una clave privada (upload_key.html). 
# Al recibir POST, se lee archivo de clave privada y te lleva al chat.
@app.route('/upload_key', methods=['GET', 'POST'])
def upload_key():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            private_key = file.read()
            # Aquí puedes guardar la llave privada de forma segura
            return redirect(url_for('chat'))
    return render_template('upload_key.html')

#Genera un par de claves RSA, la privada y públuca. La clave privada se cifra usando AES
# y ambas claves se guardan en archivos. La clave privada se descarga automáticamente.
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

#Muestra  chat.html si el usuario está en la sesión. Si no, redirige a login.
@app.route('/chat')
def chat():
    if 'username' in session:
        return render_template('chat.html', username=session['username'], users=connected_users)
    return redirect(url_for('login'))
#Cuando un usuario se conecta, se guarda su ID  y se envía un evento user_connected a todos los usuarios. 
# Despues se actualiza la lista de usuarios conectados.
@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        connected_users[username] = request.sid
        emit('user_connected', {'username': username}, broadcast=True)

        # Envía la lista completa de usuarios conectados al nuevo usuario
        emit('update_user_list', {'users': list(connected_users.keys())}, room=request.sid)
#Cuando un usuario se desconecta, se quita de connected_users y se les  notifica a los demás usuarios.
@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username in connected_users:
        del connected_users[username]
        emit('user_disconnected', {'username': username}, broadcast=True)

#Al recibir un mensaje privado, calcula un hash y una firma HMAC. 
#Envía el mensaje, el hash y la firma al destinatario.
@socketio.on('private_message')
def handle_private_message(data):
    recipient_session_id = connected_users.get(data['to'])
    if recipient_session_id:
        hashed_msg = hashlib.sha256(data['msg'].encode()).hexdigest()
        signature = hmac.new(b'secretkey', data['msg'].encode(), hashlib.sha256).hexdigest()
        emit('message', {'from': session['username'], 'msg': data['msg'], 'encrypted_msg': data['msg'], 'hash': hashed_msg, 'signature': signature}, room=recipient_session_id)
#Cifra el mensaje usando AES con una clave derivada de la contraseña
# y luego firma el mensaje cifrado. Envía el mensaje y su firma.
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
  
#Verifica la firma digital usando la clave pública del remitente. 
# Si la firma es válida, emite un evento de verificación exitosa; de lo contrario, emite un fallo.
@socketio.on('verify_signature')
def verify_signature(data):
    sender_public_key_path = os.path.join(os.getcwd(), 'public.pem')
    sender_public_key = RSA.import_key(open(sender_public_key_path).read())
    hashed_msg = SHA256.new(data['encrypted_msg'].encode())
    signature = base64.b64decode(data['signature'])
    try:
        pkcs1_15.new(sender_public_key).verify(hashed_msg, signature)
        print("Firma verificada correctamente.")
        emit('signature_verified', {'status': 'success', 'message': 'Firma verificada correctamente.'})
    except (ValueError, TypeError):
        print("Firma no válida.")
        emit('signature_verified', {'status': 'failure', 'message': 'Firma no válida.'})

if __name__ == '__main__':
    socketio.run(app, debug=True)
    