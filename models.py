# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

# Creamos la instancia de SQLAlchemy aquí. 
# La conectaremos a la aplicación en app.py para evitar importaciones circulares.
db = SQLAlchemy()

# --- 2. FUNCIÓN AYUDANTE PARA HORA CHILE ---
# NOTA IMPORTANTE:
# Este sistema usa la hora local de Chile con pytz.
# Si deseas utilizar UTC (recomendado para sistemas globales),
# reemplaza obtener_hora_chile() por datetime.utcnow
# y ajusta las funciones de timestamp en auth.py y libro.py.
def obtener_hora_chile():
    chile_tz = pytz.timezone('America/Santiago')
    # Retorna la fecha y hora actual en Chile, sin la info de zona horaria 
    # para que MySQL no se confunda (naive datetime)
    return datetime.now(chile_tz).replace(tzinfo=None)

# --- MODELOS DE CATÁLOGO ---
# Estas clases representan las tablas que contienen las opciones para los formularios.

class Rol(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    # La relación 'usuarios' nos permitirá acceder a todos los usuarios que tienen este rol.
    # ej: mi_rol.usuarios
    usuarios = db.relationship('Usuario', back_populates='rol')

class Establecimiento(db.Model):
    __tablename__ = 'establecimientos'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    usuarios = db.relationship('Usuario', back_populates='establecimiento')
    unidades = db.relationship('Unidad', back_populates='establecimiento')

class Unidad(db.Model):
    __tablename__ = 'unidades'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False) 
    usuarios = db.relationship('Usuario', back_populates='unidad')
    establecimiento_id = db.Column(db.Integer, db.ForeignKey('establecimientos.id'), nullable=False)
    establecimiento = db.relationship('Establecimiento', back_populates='unidades')

class CalidadJuridica(db.Model):
    __tablename__ = 'calidadesjuridicas'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    usuarios = db.relationship('Usuario', back_populates='calidad_juridica')

class Categoria(db.Model):
    __tablename__ = 'categorias'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(1), unique=True, nullable=False)
    usuarios = db.relationship('Usuario', back_populates='categoria')

class Factor(db.Model):
    __tablename__ = 'factores'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    # Relación para acceder a todos los subfactores de este factor.
    subfactores = db.relationship('SubFactor', back_populates='factor')

class SubFactor(db.Model):
    __tablename__ = 'subfactores'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    factor_id = db.Column(db.Integer, db.ForeignKey('factores.id'))
    # Relación para acceder al factor padre desde un subfactor. ej: mi_subfactor.factor
    factor = db.relationship('Factor', back_populates='subfactores')
    comentarios = db.relationship('Comentario', back_populates='subfactor')

# --- MODELOS PRINCIPALES ---

class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    rut = db.Column(db.String(12), unique=True, nullable=False)
    nombre_completo = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    activo = db.Column(db.Boolean, default=True)
    fecha_creacion = db.Column(db.DateTime, default=obtener_hora_chile)
    cambio_clave_requerido = db.Column(db.Boolean, default=False, nullable=False)
    reset_token = db.Column(db.String(32), nullable=True)
    reset_token_expiracion = db.Column(db.DateTime, nullable=True)

    # --- Llaves Foráneas y Relaciones ---
    rol_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    establecimiento_id = db.Column(db.Integer, db.ForeignKey('establecimientos.id'))
    unidad_id = db.Column(db.Integer, db.ForeignKey('unidades.id'))
    calidad_juridica_id = db.Column(db.Integer, db.ForeignKey('calidadesjuridicas.id'))
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'))
    
    # Relaciones que nos permiten usar la "notación de punto". ej: mi_usuario.rol.nombre
    rol = db.relationship('Rol', back_populates='usuarios')
    establecimiento = db.relationship('Establecimiento', back_populates='usuarios')
    unidad = db.relationship('Unidad', back_populates='usuarios')
    calidad_juridica = db.relationship('CalidadJuridica', back_populates='usuarios')
    categoria = db.relationship('Categoria', back_populates='usuarios')

    # --- Relación Reflexiva (Jefe/Subordinado) ---
    jefe_directo_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=True)
    # Esta relación nos permite tener una lista de 'subordinados' para un usuario (jefe).
    subordinados = db.relationship('Usuario',
                                  backref=db.backref('jefe_directo', remote_side=[id]),
                                  lazy='dynamic')

    # --- Métodos para la gestión de contraseñas ---
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Comentario(db.Model):
    __tablename__ = 'comentarios' # Coincide con el ALTER TABLE
    folio = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.Enum('Favorable', 'Desfavorable'), nullable=False)
    motivo_jefe = db.Column(db.Text, nullable=False)
    observacion_funcionario = db.Column(db.Text)
    estado = db.Column(db.Enum('Pendiente', 'Aceptada'), default='Pendiente')
    fecha_creacion = db.Column(db.Date, nullable=False)
    fecha_aceptacion = db.Column(db.DateTime)
    
    # Llaves Foráneas
    funcionario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    jefe_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    subfactor_id = db.Column(db.Integer, db.ForeignKey('subfactores.id'), nullable=False)

    # Relaciones
    subfactor = db.relationship('SubFactor', back_populates='comentarios')
    
    # Como hay dos relaciones a la misma tabla (Usuarios), debemos ser explícitos.
    funcionario = db.relationship('Usuario', foreign_keys=[funcionario_id], backref='comentarios_recibidos')
    jefe = db.relationship('Usuario', foreign_keys=[jefe_id], backref='comentarios_emitidos')

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    # Usamos datetime.utcnow para guardar la hora en UTC (más estándar)
    timestamp = db.Column(db.DateTime, nullable=False, default=obtener_hora_chile) 
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=True) # Permitimos NULL
    usuario_nombre = db.Column(db.String(255))
    accion = db.Column(db.String(255), nullable=False)
    detalles = db.Column(db.Text)

    # Relación opcional para poder acceder al objeto Usuario desde un Log
    # Usamos backref para poder hacer usuario.logs si es necesario en el futuro
    # Y lazy='joined' para que cargue los datos del usuario automáticamente si se necesitan
    usuario = db.relationship('Usuario', backref=db.backref('logs', lazy=True), foreign_keys=[usuario_id])