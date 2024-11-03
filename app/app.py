from flask import Flask, render_template, request, redirect, url_for, session, send_file,  jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad  # Importa unpad para manejar el padding
import base64
from flask_socketio import SocketIO, send, emit
import hashlib
import json

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
        password = request.form['password'].encode()  # Contraseña ingresada para descifrado

        print("Contraseña ingresada por el usuario para descifrar:", password.decode())  # Imprimir contraseña ingresada

        if file:
            # Leer el contenido del archivo .pem y eliminar encabezado/pie de página
            pem_data = file.read().decode('utf-8')
            pem_content = pem_data.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "").replace("-----END ENCRYPTED PRIVATE KEY-----", "").strip()
            
            # Dividir el contenido en las tres partes (salt, iv, ciphertext) basadas en líneas
            lines = pem_content.splitlines()
            if len(lines) < 3:
                flash("Error: Formato del archivo PEM no válido.")
                return redirect(url_for('upload_key'))

            # Decodificar cada parte del PEM (salt, iv, ciphertext)
            salt = base64.b64decode(lines[0])
            iv = base64.b64decode(lines[1])
            ciphertext = base64.b64decode(lines[2])

            print("Salt al descifrar:", base64.b64encode(salt).decode())
            print("IV al descifrar:", base64.b64encode(iv).decode())
            print("Ciphertext al descifrar:", base64.b64encode(ciphertext).decode())

            # Derivar la clave usando PBKDF2 con el salt
            derived_key = PBKDF2(password, salt, dkLen=32, count=1000)
            print("Clave derivada en el descifrado:", base64.b64encode(derived_key).decode())

            # Crear el objeto de cifrado AES en modo CTR con el iv
            cipher = AES.new(derived_key, AES.MODE_CTR, nonce=iv)

            try:
                decrypted_data = cipher.decrypt(ciphertext)

                # Convertir los datos descifrados a base64 para asegurar que no haya caracteres no válidos
                base64_encoded_key = base64.b64encode(decrypted_data).decode('utf-8')

                # Añadir encabezado y pie de página para que coincida con el formato PEM
                private_key_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                private_key_pem += base64_encoded_key
                private_key_pem += "\n-----END RSA PRIVATE KEY-----\n"

                print("Clave privada descifrada en formato PEM:\n", private_key_pem)

                # Intentar importar la clave para verificar si el formato es correcto
                try:
                    rsa_key = RSA.import_key(private_key_pem)
                    print("Clave privada RSA importada correctamente.")
                    flash("Clave privada descifrada e importada exitosamente.")
                    return redirect(url_for('chat'))
                except ValueError as e:
                    print("Error al importar la clave privada:", e)
                    flash("Error de formato en la clave privada descifrada.")
                    return redirect(url_for('upload_key'))

            except ValueError as e:
                flash("Contraseña incorrecta o archivo alterado.")
                print("Error en el descifrado:", e)
                return redirect(url_for('upload_key'))

    return render_template('upload_key.html')








# Ruta para generar claves y enviar clave privada al cliente para cifrar
@app.route('/generate_keys')
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key()

    public_key_path = os.path.join(os.getcwd(), 'public.pem')
    with open(public_key_path, 'wb') as f:
        f.write(public_key)

    print("Clave privada generada en el servidor:", private_key)  # Verificar que la clave privada se genera correctamente

    return render_template('encrypt_and_download.html', private_key=private_key)

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

    try:
        # Intentar cargar e importar la clave privada
        private_key_path = os.path.join(os.getcwd(), 'private.pem')
        
        # Leer el contenido de la clave privada y verificar formato
        with open(private_key_path, 'rb') as f:
            private_key_data = f.read()
        
        print("Contenido de la clave privada (hex):", private_key_data.hex())
        
        try:
            private_key = RSA.import_key(private_key_data)
            print("Clave privada importada exitosamente.")
        except ValueError as e:
            print("Error de formato de la clave privada:", e)
            flash("Error al importar la clave privada: formato no soportado.")
            return  # Termina aquí si hay un error de formato
        
        # Crear firma digital
        hashed_msg = SHA256.new(encrypted_msg.encode())
        signature = pkcs1_15.new(private_key).sign(hashed_msg)
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        send({'username': usuario, 'msg': msg, 'encrypted_msg': encrypted_msg, 'hash': hashed_msg.hexdigest(), 'signature': signature_b64}, broadcast=True)

    except Exception as e:
        print("Error inesperado al firmar el mensaje:", e)
        flash("Error inesperado al procesar el mensaje.")




if __name__ == '__main__':
    socketio.run(app, debug=True)