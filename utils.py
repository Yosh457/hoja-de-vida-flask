# utils.py
import os
import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from flask import abort, redirect, url_for, flash
from flask_login import current_user
from datetime import datetime, timedelta
from models import db, Log, Usuario # Importamos los modelos necesarios

# --- DECORADORES DE ROL ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.rol.nombre != 'Admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def jefa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.rol.nombre not in ['Admin', 'Jefa Salud']):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def encargado_unidad_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.rol.nombre not in ['Admin', 'Jefa Salud', 'Encargado de Unidad']):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def encargado_recinto_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.rol.nombre not in ['Admin', 'Jefa Salud', 'Encargado de Recinto']):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def check_password_change(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.cambio_clave_requerido:
            # ¡Importante! Usamos el nombre del futuro blueprint: 'auth.cambiar_clave'
            return redirect(url_for('auth.cambiar_clave'))
        return f(*args, **kwargs)
    return decorated_function

# --- FUNCIONES DE LÓGICA ---
def es_superior_jerarquico(usuario_actual, funcionario_a_ver):
    if not funcionario_a_ver.jefe_directo:
        return False
    jefe_actual = funcionario_a_ver.jefe_directo
    while jefe_actual:
        if jefe_actual.id == usuario_actual.id:
            return True
        jefe_actual = jefe_actual.jefe_directo
    return False

# --- FUNCIONES DE CORREO ---
def enviar_correo_reseteo(usuario, token):
    remitente = os.getenv("EMAIL_USUARIO")
    contrasena = os.getenv("EMAIL_CONTRASENA")
    if not remitente or not contrasena:
        print("ERROR: Credenciales de correo no configuradas en .env")
        return
    msg = MIMEMultipart()
    msg['Subject'] = 'Restablecimiento de Contraseña - Sistema Libro de Novedades'
    msg['From'] = f"Sistema Libro de Novedades <{remitente}>"
    msg['To'] = usuario.email
    # ¡Importante! Usamos 'auth.resetear_clave'
    url_reseteo = url_for('auth.resetear_clave', token=token, _external=True)
    cuerpo_html = f"""
    <p>Hola {usuario.nombre_completo},</p>
    <p>Recibiste este correo porque se solicitó un restablecimiento de contraseña.</p>
    <p><a href="{url_reseteo}" style="padding: 10px 15px; background-color: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">Restablecer mi contraseña</a></p>
    <p>El enlace expirará en 1 hora.</p>
    """
    msg.attach(MIMEText(cuerpo_html, 'html'))
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(remitente, contrasena)
            server.send_message(msg)
    except Exception as e:
        print(f"Error al enviar correo de reseteo: {e}")

def enviar_correo_notificacion_comentario(comentario):
    remitente = os.getenv("EMAIL_USUARIO")
    contrasena = os.getenv("EMAIL_CONTRASENA")
    if not remitente or not contrasena:
        print("ERROR: Credenciales de correo no configuradas en .env")
        return
    funcionario = comentario.funcionario
    jefe = comentario.jefe
    msg = MIMEMultipart()
    msg['Subject'] = f"Nuevo Comentario en tu Libro de Novedades - Folio #{comentario.folio}"
    msg['From'] = f"Sistema Libro de Novedades <{remitente}>"
    msg['To'] = funcionario.email
    # ¡Importante! Usamos 'auth.login'
    url_sistema = url_for('auth.login', _external=True)
    cuerpo_html = f"""
    <p>Hola {funcionario.nombre_completo},</p>
    <p>Has recibido un nuevo comentario de tipo <strong>{comentario.tipo}</strong> en tu Libro de Novedades, creado por <strong>{jefe.nombre_completo}</strong>.</p>
    <p>Para revisar los detalles, por favor ingresa al sistema:</p>
    <p><a href="{url_sistema}" style="padding: 10px 15px; background-color: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">Ingresar al Sistema</a></p>
    """
    msg.attach(MIMEText(cuerpo_html, 'html'))
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(remitente, contrasena)
            server.send_message(msg)
    except Exception as e:
        print(f"Error al enviar correo de notificación: {e}")

# --- FUNCIÓN DE LOGGING ---
def registrar_log(accion, detalles=""):
    user_id = current_user.id if current_user.is_authenticated else None
    user_name = current_user.nombre_completo if current_user.is_authenticated else "Sistema"
    nuevo_log = Log(
        usuario_id=user_id,
        usuario_nombre=user_name,
        accion=accion,
        detalles=detalles
    )
    db.session.add(nuevo_log)