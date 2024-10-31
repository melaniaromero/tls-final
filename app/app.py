from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)
app.secret_key = 'clave_secreta_segura'  # Clave para la sesión de Flask

# Base de datos en memoria para credenciales (simulación)
users = {}

# Ruta de registro de usuario
@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            return "Usuario ya registrado. Intenta con otro nombre."

        hashed_password = generate_password_hash(password)
        users[username] = hashed_password
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_password = users.get(username)
        if user_password and check_password_hash(user_password, password):
            session['username'] = username
            return redirect(url_for('chat.html'))
        else:
            return "Credenciales incorrectas."

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
