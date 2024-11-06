from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Tabla de asociación para misiones aceptadas
misiones_aceptadas = db.Table('misiones_aceptadas',
    db.Column('usuario_id', db.Integer, db.ForeignKey('usuarios.id'), primary_key=True),
    db.Column('mision_id', db.Integer, db.ForeignKey('misiones.id'), primary_key=True)
)

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    misiones_creadas = db.relationship('Mision', backref='creador', lazy=True)

class Mision(db.Model):
    __tablename__ = 'misiones'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    voluntarios = db.Column(db.Integer, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    comentarios = db.relationship('Comentario', backref='mision_relacionada', lazy=True)

class Comentario(db.Model):
    __tablename__ = 'comentarios'
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    mision_id = db.Column(db.Integer, db.ForeignKey('misiones.id'), nullable=False)
    usuario = db.relationship('Usuario', backref='comentarios', lazy=True)
