# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Creamos la instancia de SQLAlchemy aquí. 
# La conectaremos a la aplicación en app.py para evitar importaciones circulares.
db = SQLAlchemy()

# --- MODELOS DE CATÁLOGO ---
# Estas clases representan las tablas que contienen las opciones para los formularios.

class Rol(db.Model):
    __tablename__ = 'Roles'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    # La relación 'usuarios' nos permitirá acceder a todos los usuarios que tienen este rol.
    # ej: mi_rol.usuarios
    usuarios = db.relationship('Usuario', back_populates='rol')

class Establecimiento(db.Model):
    __tablename__ = 'Establecimientos'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    usuarios = db.relationship('Usuario', back_populates='establecimiento')

class Unidad(db.Model):
    __tablename__ = 'Unidades'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    usuarios = db.relationship('Usuario', back_populates='unidad')

class CalidadJuridica(db.Model):
    __tablename__ = 'CalidadesJuridicas'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    usuarios = db.relationship('Usuario', back_populates='calidad_juridica')

class Categoria(db.Model):
    __tablename__ = 'Categorias'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(1), unique=True, nullable=False)
    usuarios = db.relationship('Usuario', back_populates='categoria')

class Factor(db.Model):
    __tablename__ = 'Factores'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    # Relación para acceder a todos los subfactores de este factor.
    subfactores = db.relationship('SubFactor', back_populates='factor')

class SubFactor(db.Model):
    __tablename__ = 'SubFactores'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    factor_id = db.Column(db.Integer, db.ForeignKey('Factores.id'))
    # Relación para acceder al factor padre desde un subfactor. ej: mi_subfactor.factor
    factor = db.relationship('Factor', back_populates='subfactores')
    anotaciones = db.relationship('Anotacion', back_populates='subfactor')

# --- MODELOS PRINCIPALES ---

class Usuario(db.Model, UserMixin):
    __tablename__ = 'Usuarios'
    id = db.Column(db.Integer, primary_key=True)
    rut = db.Column(db.String(12), unique=True, nullable=False)
    nombre_completo = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    activo = db.Column(db.Boolean, default=True)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)

    # --- Llaves Foráneas y Relaciones ---
    rol_id = db.Column(db.Integer, db.ForeignKey('Roles.id'))
    establecimiento_id = db.Column(db.Integer, db.ForeignKey('Establecimientos.id'))
    unidad_id = db.Column(db.Integer, db.ForeignKey('Unidades.id'))
    calidad_juridica_id = db.Column(db.Integer, db.ForeignKey('CalidadesJuridicas.id'))
    categoria_id = db.Column(db.Integer, db.ForeignKey('Categorias.id'))
    
    # Relaciones que nos permiten usar la "notación de punto". ej: mi_usuario.rol.nombre
    rol = db.relationship('Rol', back_populates='usuarios')
    establecimiento = db.relationship('Establecimiento', back_populates='usuarios')
    unidad = db.relationship('Unidad', back_populates='usuarios')
    calidad_juridica = db.relationship('CalidadJuridica', back_populates='usuarios')
    categoria = db.relationship('Categoria', back_populates='usuarios')

    # --- Relación Reflexiva (Jefe/Subordinado) ---
    jefe_directo_id = db.Column(db.Integer, db.ForeignKey('Usuarios.id'), nullable=True)
    # Esta relación nos permite tener una lista de 'subordinados' para un usuario (jefe).
    subordinados = db.relationship('Usuario',
                                  backref=db.backref('jefe_directo', remote_side=[id]),
                                  lazy='dynamic')

    # --- Métodos para la gestión de contraseñas ---
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Anotacion(db.Model):
    __tablename__ = 'Anotaciones'
    folio = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.Enum('Favorable', 'Desfavorable'), nullable=False)
    motivo_jefe = db.Column(db.Text, nullable=False)
    observacion_funcionario = db.Column(db.Text)
    estado = db.Column(db.Enum('Pendiente', 'Leída'), default='Pendiente')
    fecha_creacion = db.Column(db.Date, nullable=False)
    fecha_aceptacion = db.Column(db.DateTime)
    
    # Llaves Foráneas
    funcionario_id = db.Column(db.Integer, db.ForeignKey('Usuarios.id'), nullable=False)
    jefe_id = db.Column(db.Integer, db.ForeignKey('Usuarios.id'), nullable=False)
    subfactor_id = db.Column(db.Integer, db.ForeignKey('SubFactores.id'), nullable=False)

    # Relaciones
    subfactor = db.relationship('SubFactor', back_populates='anotaciones')
    
    # Como hay dos relaciones a la misma tabla (Usuarios), debemos ser explícitos.
    funcionario = db.relationship('Usuario', foreign_keys=[funcionario_id], backref='anotaciones_recibidas')
    jefe = db.relationship('Usuario', foreign_keys=[jefe_id], backref='anotaciones_emitidas')