from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from database import connectToMySQL    # Asumiendo que tienes un archivo database.py
from flask_wtf.csrf import CSRFProtect, generate_csrf
import re
import smtplib
from email.mime.text import MIMEText
from flask import url_for
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import itsdangerous
from itsdangerous import URLSafeTimedSerializer
from itsdangerous import Serializer
from models import Mision, Usuario, Comentario
import os

app = Flask(__name__)
app.secret_key = 'clave_secreta_aqui'  # Cambiar en producción
bcrypt = Bcrypt(app)

# Inicializar CSRF protection
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Si no la tienes ya configurada

# Agregar esta función para generar el token CSRF
@app.context_processor
def inject_csrf_token():
    token = generate_csrf()
    return dict(csrf_token=token)

# Constantes de validación
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$')

# Configuración para tokens seguros
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Agregar decorador para verificar si el usuario está logueado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Rutas para autenticación
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if 'usuario_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if len(nombre) < 2:
            flash('El nombre debe tener al menos 2 caracteres', 'error')
        elif not EMAIL_REGEX.match(email):
            flash('Por favor introduce un email válido', 'error')
        elif not PASSWORD_REGEX.match(password):
            flash('La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número', 'error')
        elif password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
        else:
            existing_user = Usuario.query.filter_by(email=email).first()
            if existing_user:
                flash('El email ya está registrado', 'error')
            else:
                pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = Usuario(nombre=nombre, email=email, password=pw_hash)
                db.session.add(new_user)
                db.session.commit()
                session['usuario_id'] = new_user.id
                session['usuario_nombre'] = new_user.nombre
                return redirect(url_for('index'))

    return render_template('registro.html')

@app.route('/')
@login_required
def index():
    try:
        misiones = Mision.query.all()
        total_pages = 1  # Cambia esto por tu lógica de paginación
        return render_template('index.html', misiones=misiones, total_pages=total_pages, page=1)
    except Exception as e:
        flash('Error al cargar las misiones: ' + str(e), 'error')
        return render_template('index.html', misiones=[], total_pages=0, page=1)

@app.route('/misiones/nueva', methods=['GET', 'POST'])
def nueva_mision():
    if 'usuario_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        # Validaciones
        if len(request.form['titulo']) < 1:
            flash('El título es requerido')
            return redirect('/misiones/nueva')
        
        if not 2 <= int(request.form['voluntarios']) <= 20:
            flash('El número de voluntarios debe estar entre 2 y 20')
            return redirect('/misiones/nueva')
        
        # Insertar misión usando SQLAlchemy
        nueva_mision = Mision(
            titulo=request.form['titulo'],
            descripcion=request.form['descripcion'],
            voluntarios=request.form['voluntarios'],
            usuario_id=session['usuario_id']
        )
        db.session.add(nueva_mision)
        db.session.commit()
        return redirect('/')
    
    return render_template('nueva_mision.html')

@app.route('/misiones/<int:id>/editar', methods=['GET', 'POST'])
def editar_mision(id):
    if 'usuario_id' not in session:
        return redirect('/login')
    
    mysql = connectToMySQL('misiones')
    
    # Verificar que el usuario sea el creador
    query = "SELECT * FROM misiones WHERE id = %(id)s AND usuario_id = %(usuario_id)s"
    data = {'id': id, 'usuario_id': session['usuario_id']}
    mision = mysql.query_db(query, data)
    
    if not mision:
        return redirect('/')
    
    if request.method == 'POST':
        # Mismas validaciones que en crear
        if len(request.form['titulo']) < 1:
            flash('El título es requerido')
            return redirect(f'/misiones/{id}/editar')
        
        # Actualizar misión
        query = """UPDATE misiones SET titulo=%(titulo)s, descripcion=%(descripcion)s, 
                  voluntarios=%(voluntarios)s WHERE id = %(id)s"""
        data = {
            'id': id,
            'titulo': request.form['titulo'],
            'descripcion': request.form['descripcion'],
            'voluntarios': request.form['voluntarios']
        }
        mysql.query_db(query, data)
        return redirect('/')
    
    return render_template('editar_mision.html', mision=mision[0])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'usuario_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = Usuario.query.filter_by(email=email).first()
        
        if user:
            print(f"Stored hash: {user.password}")  # Log the stored hash
            print(f"Entered password: {password}")  # Log the entered password

        try:
            if user and bcrypt.check_password_hash(user.password, password):
                session['usuario_id'] = user.id
                session['usuario_nombre'] = user.nombre
                return redirect(url_for('index'))
            else:
                flash('Email o contraseña incorrectos', 'error')
        except ValueError as e:
            print(f"Error checking password hash: {e}")
            flash('Error al verificar la contraseña. Por favor, intenta de nuevo.', 'error')
    
    return render_template('login.html')

@app.route('/misiones/<int:id>/eliminar')
def eliminar_mision(id):
    if 'usuario_id' not in session:
        return redirect('/login')
    
    mysql = connectToMySQL('misiones')
    query = "DELETE FROM misiones WHERE id = %(id)s AND usuario_id = %(usuario_id)s"
    data = {
        'id': id,
        'usuario_id': session['usuario_id']
    }
    mysql.query_db(query, data)
    return redirect('/')

@app.route('/misiones/<int:id>')
def ver_mision(id):
    if 'usuario_id' not in session:
        return redirect('/login')
    
    mision = Mision.query.get_or_404(id)
    
    return render_template('ver_mision.html', mision=mision)

@app.route('/recuperar-password', methods=['GET', 'POST'])
def recuperar_password():
    if request.method == 'POST':
        try:
            email = request.form['email']
            mysql = connectToMySQL('misiones')
            query = "SELECT * FROM usuarios WHERE email = %(email)s"
            usuario = mysql.query_db(query, {'email': email})
            
            if usuario:
                # Generar token
                token = serializer.dumps(email, salt='recover-password')
                
                # Enviar email
                reset_url = url_for('reset_password', token=token, _external=True)
                send_password_reset_email(email, reset_url)
                
                flash('Se ha enviado un enlace de recuperación a tu email', 'success')
            else:
                flash('No existe una cuenta con ese email', 'error')
                
        except Exception as e:
            flash('Ocurrió un error. Por favor, intenta más tarde.', 'error')
            
    return render_template('recuperar_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='recover-password', max_age=3600)  # Token válido por 1 hora
    except:
        flash('El enlace de recuperación es inválido o ha expirado', 'error')
        return redirect('/login')
    
    if request.method == 'POST':
        # Validar nueva contraseña
        if not PASSWORD_REGEX.match(request.form['password']):
            flash('La contraseña debe tener al menos 8 caracteres...', 'error')
            return redirect(url_for('reset_password', token=token))
            
        try:
            pw_hash = bcrypt.generate_password_hash(request.form['password'])
            mysql = connectToMySQL('misiones')
            query = "UPDATE usuarios SET password = %(password)s WHERE email = %(email)s"
            mysql.query_db(query, {'email': email, 'password': pw_hash})
            
            flash('Tu contraseña ha sido actualizada', 'success')
            return redirect('/login')
            
        except Exception as e:
            flash('Ocurrió un error al actualizar tu contraseña', 'error')
            
    return render_template('reset_password.html')

def send_password_reset_email(email, reset_url):
    sender = "your-email@example.com"  # Replace with your email
    password = "your-app-password"     # Replace with your email password
    
    msg = MIMEText(f'Click aquí para restablecer tu contraseña: {reset_url}')
    msg['Subject'] = 'Recuperación de Contraseña'
    msg['From'] = sender
    msg['To'] = email
    
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(sender, password)
        server.send_message(msg)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Usuario.query.filter_by(email=email).first()
        
        if user:
            # Generar token
            token = user.get_reset_token()
            # Crear URL de reset
            reset_url = url_for('reset_password', token=token, _external=True)
            # Enviar email
            send_password_reset_email(email, reset_url)
            flash('Se ha enviado un enlace de recuperación a tu email', 'success')
            return redirect(url_for('login'))
            
        flash('No existe una cuenta con ese email', 'error')
    return render_template('forgot_password.html')

@app.route('/misiones/<int:id>/comentar', methods=['POST'])
def comentar_mision(id):
    if 'usuario_id' not in session:
        return redirect('/login')
    
    texto = request.form['comentario']
    nuevo_comentario = Comentario(
        texto=texto,
        usuario_id=session['usuario_id'],
        mision_id=id
    )
    db.session.add(nuevo_comentario)
    db.session.commit()
    
    return redirect(url_for('ver_mision', id=id))

@app.route('/misiones/<int:id>/aceptar', methods=['POST'])
def aceptar_mision(id):
    if 'usuario_id' not in session:
        return redirect('/login')

    mision = Mision.query.get(id)
    usuario = Usuario.query.get(session['usuario_id'])

    if usuario not in mision.aceptados:
        mision.aceptados.append(usuario)
        db.session.commit()

    return redirect(url_for('ver_mision', id=id))

# Configuración de SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/misiones'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the association table for the many-to-many relationship
misiones_aceptadas = db.Table('misiones_aceptadas',
    db.Column('mision_id', db.Integer, db.ForeignKey('misiones.id'), primary_key=True),
    db.Column('usuario_id', db.Integer, db.ForeignKey('usuarios.id'), primary_key=True)
)

# Modelo de Misión
class Mision(db.Model):
    __tablename__ = 'misiones'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    voluntarios = db.Column(db.Integer, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    creador = db.relationship('Usuario', backref='misiones_creadas', lazy=True)
    aceptados = db.relationship('Usuario', secondary=misiones_aceptadas, backref='misiones_aceptadas', lazy='dynamic')

# Modelo de Usuario
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # No es necesario definir 'misiones' aquí si usas backref en 'Mision'

# Ensure sensitive information is stored securely
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')  # Use environment variable

# After your db and model definitions, but before running the app
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
