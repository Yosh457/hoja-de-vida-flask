# blueprints/auth.py
from flask import (
    render_template, redirect, url_for, flash, request, Blueprint
)
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import pytz
import secrets

# Importamos las dependencias
from models import db, Usuario
from utils import registrar_log, enviar_correo_reseteo

# 1. Creamos el Blueprint
auth_bp = Blueprint(
    'auth', __name__,
    template_folder='../templates' # Le decimos dónde buscar los templates
)

# --- DICCIONARIO DE REDIRECCIONES ---
# Define a dónde va cada rol. Si agregas un rol nuevo, solo editas esto.
RUTAS_POR_ROL = {
    "Admin": "admin.admin_panel",
    "Jefa Salud": "jefa_salud.panel_jefa_salud",
    "Encargado de Recinto": "recinto.panel_encargado_recinto",
    "Encargado de Unidad": "unidad.panel_encargado_unidad",
    "default": "libro.mi_libro_novedades" # Para Funcionario y cualquier otro
}
def obtener_ruta_redireccion(usuario):
    """Devuelve la URL de redirección basada en el rol del usuario."""
    # .get(clave, valor_por_defecto) busca el rol, si no existe usa el default
    endpoint = RUTAS_POR_ROL.get(usuario.rol.nombre, RUTAS_POR_ROL["default"])
    return url_for(endpoint)

# 2. Movemos todas las rutas de autenticación aquí
# y cambiamos @app.route por @auth_bp.route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # 1. Redirección inteligente si ya está logueado
    if current_user.is_authenticated:
        return redirect(obtener_ruta_redireccion(current_user))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario:
            if not usuario.activo:
                flash('Tu cuenta ha sido desactivada.', 'danger')
                return redirect(url_for('auth.login'))

        if not usuario or not usuario.check_password(password):
            flash('Email o contraseña incorrectos.', 'danger')
            return redirect(url_for('auth.login'))
        
        login_user(usuario)
        registrar_log(accion="Inicio de Sesión", detalles=f"Usuario {usuario.nombre_completo} (ID: {usuario.id}) inició sesión.")
        db.session.commit()
        flash('¡Has iniciado sesión correctamente!', 'success')
        
        # 2. Redirección inteligente después del login
        return redirect(obtener_ruta_redireccion(usuario))

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    registrar_log(accion="Cierre de Sesión", detalles=f"Usuario {current_user.nombre_completo} (ID: {current_user.id}) cerró sesión.")
    db.session.commit()
    logout_user()
    flash('Has cerrado la sesión.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/cambiar_clave', methods=['GET', 'POST'])
@login_required
def cambiar_clave():
    if not current_user.cambio_clave_requerido:
        return redirect(url_for('auth.login')) # Redirigimos al login
    if request.method == 'POST':
        nueva_password = request.form.get('nueva_password')
        current_user.set_password(nueva_password)
        current_user.cambio_clave_requerido = False
        db.session.commit()
        logout_user()
        flash('Contraseña actualizada. Por favor, inicia sesión de nuevo.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('cambiar_clave.html')

@auth_bp.route('/solicitar-reseteo', methods=['GET', 'POST'])
def solicitar_reseteo():
    if request.method == 'POST':
        email = request.form.get('email')
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario:
            token = secrets.token_hex(16)
            chile_tz = pytz.timezone('America/Santiago')
            ahora_chile = datetime.now(chile_tz).replace(tzinfo=None)
            expiracion = ahora_chile + timedelta(hours=1)
            usuario.reset_token = token
            usuario.reset_token_expiracion = expiracion
            db.session.commit()
            enviar_correo_reseteo(usuario, token)
            flash(f'Se ha enviado un enlace para restablecer la contraseña a {email}.', 'success')
        else:
            flash(f'El correo {email} no se encuentra registrado.', 'danger')
        return redirect(url_for('auth.login'))
    return render_template('solicitar_reseteo.html')

@auth_bp.route('/resetear-clave/<token>', methods=['GET', 'POST'])
def resetear_clave(token):
    usuario = Usuario.query.filter_by(reset_token=token).first()
    chile_tz = pytz.timezone('America/Santiago')
    ahora_chile = datetime.now(chile_tz).replace(tzinfo=None)
    if not usuario or usuario.reset_token_expiracion < ahora_chile:
        flash('El enlace de reseteo es inválido o ha expirado.', 'danger')
        return redirect(url_for('auth.solicitar_reseteo'))
    if request.method == 'POST':
        nueva_password = request.form.get('nueva_password')
        usuario.set_password(nueva_password)
        usuario.reset_token = None
        usuario.reset_token_expiracion = None
        db.session.commit()
        flash('Tu contraseña ha sido actualizada. Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('resetear_clave.html')