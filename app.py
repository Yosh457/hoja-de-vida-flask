# app.py

import os
from dotenv import load_dotenv
from flask import Flask
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
# Importamos las extensiones y los modelos que usaremos
from flask_login import LoginManager
from models import db, Usuario, Rol, Establecimiento, Unidad, CalidadJuridica, Categoria, Anotacion, Factor, SubFactor
from datetime import date, datetime, timedelta
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from functools import wraps
from flask import abort
from flask_login import current_user
# Inicializamos el gestor de logins
login_manager = LoginManager()

# --- DECORADOR DE ROL ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Si el usuario no es admin, mostramos un error de "no autorizado"
        if not current_user.is_authenticated or current_user.rol.nombre != 'Admin':
            abort(403) # Error 403: Forbidden
        return f(*args, **kwargs)
    return decorated_function

# --- DECORADOR DE ROL JEFE ---
def jefe_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Permitimos el acceso si el usuario es Admin O Jefe.
        if not current_user.is_authenticated or (current_user.rol.nombre not in ['Admin', 'Jefe']):
            abort(403) # Error 403: Forbidden
        return f(*args, **kwargs)
    return decorated_function

def check_password_change(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.cambio_clave_requerido:
            return redirect(url_for('cambiar_clave'))
        return f(*args, **kwargs)
    return decorated_function

def create_app():
    """Crea y configura la aplicación Flask."""
    # Inicializamos la aplicación Flask
    app = Flask(__name__)
    # Cargar las variables de entorno desde el archivo .env
    load_dotenv()

    # --- CONFIGURACIÓN DE LA APLICACIÓN ---
    # 1. Clave secreta para proteger las sesiones y formularios
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    
    # 2. Configuración de la base de datos con SQLAlchemy
    # Formato: mysql+pymysql://usuario:contraseña@servidor/nombre_db
    db_user = 'root'
    db_password = os.getenv('MYSQL_PASSWORD')
    db_name = 'hoja_de_vida_db'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@localhost/{db_name}'
    # Opcional: Desactiva una advertencia de SQLAlchemy
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # --- INICIALIZACIÓN DE EXTENSIONES ---
    
    # Conectamos nuestra instancia 'db' (importada de models) con la aplicación.
    db.init_app(app)

    # Conectamos el gestor de logins con la aplicación
    login_manager.init_app(app)
    
    # Le decimos a Flask-Login cuál es la página de inicio de sesión.
    # Si un usuario no autenticado intenta acceder a una página protegida, será redirigido aquí.
    login_manager.login_view = 'login' 
    login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'
    login_manager.login_message_category = 'warning' # Para que los mensajes flash se vean bonitos


    # --- RUTAS ---
    @app.route('/')
    def index():
        # Redirigimos a la página de login por defecto
        from flask import redirect, url_for
        return redirect(url_for('login'))
    
    # --- RUTAS DE AUTENTICACIÓN ---
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # Si el usuario ya está autenticado, lo redirigimos a su panel correspondiente
        if current_user.is_authenticated:
            if current_user.rol.nombre == 'Admin':
                return redirect(url_for('admin_panel'))
            elif current_user.rol.nombre == 'Jefe':
                return redirect(url_for('panel_jefe'))
            else:
                return redirect(url_for('mi_hoja_de_vida'))

        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Buscamos al usuario por su email en la base de datos
            usuario = Usuario.query.filter_by(email=email).first()

            # Verificamos primero si el usuario existe, y LUEGO si está activo.
            if usuario:
                if not usuario.activo:
                    flash('Tu cuenta ha sido desactivada. Por favor, contacta a un administrador.', 'danger')
                    return redirect(url_for('login'))

            # Verificamos si el usuario existe y si la contraseña es correcta
            if not usuario or not usuario.check_password(password):
                flash('Email o contraseña incorrectos. Por favor, inténtalo de nuevo.', 'danger')
                return redirect(url_for('login'))
            
            # Si todo es correcto, iniciamos la sesión del usuario
            login_user(usuario)
            flash('¡Has iniciado sesión correctamente!', 'success')
            # --- LÓGICA DE REDIRECCIÓN POR ROL ---
            if usuario.rol.nombre == 'Admin':
                return redirect(url_for('admin_panel'))
            elif usuario.rol.nombre == 'Jefe':
                return redirect(url_for('panel_jefe'))
            else:
                return redirect(url_for('mi_hoja_de_vida'))

        # Si el método es GET, simplemente mostramos la página de login
        return render_template('login.html')

    @app.route('/logout')
    @login_required # Solo un usuario logueado puede desloguearse
    def logout():
        logout_user()
        flash('Has cerrado la sesión.', 'success')
        return redirect(url_for('login'))
    
    # --- RUTAS DEL PANEL DE ADMINISTRACIÓN ---
    @app.route('/admin/panel')
    @login_required
    @check_password_change
    @admin_required # ¡Aplicamos nuestro decorador personalizado!
    def admin_panel():
        # Obtenemos todos los usuarios y los ordenamos por ID
        usuarios = Usuario.query.order_by(Usuario.id).all()
        return render_template('admin_panel.html', usuarios=usuarios)
    
    @app.route('/admin/crear_usuario', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def crear_usuario():
        if request.method == 'POST':
            # 1. Recolectamos los datos del formulario
            rut = request.form.get('rut')
            nombre = request.form.get('nombre_completo')
            email = request.form.get('email')
            password = request.form.get('password')
            rol_id = request.form.get('rol_id')
            unidad_id = request.form.get('unidad_id')
            establecimiento_id = request.form.get('establecimiento_id')
            calidad_id = request.form.get('calidad_id')
            categoria_id = request.form.get('categoria_id')
            jefe_id = request.form.get('jefe_directo_id')
            forzar_cambio = request.form.get('forzar_cambio_clave') == '1'

            # 2. Verificamos si el email o RUT ya existen
            if Usuario.query.filter_by(email=email).first():
                flash('El correo electrónico ya está registrado.', 'danger')
                return redirect(url_for('crear_usuario'))
            if Usuario.query.filter_by(rut=rut).first():
                flash('El RUT ya está registrado.', 'danger')
                return redirect(url_for('crear_usuario'))

            # 3. Creamos la nueva instancia de Usuario
            nuevo_usuario = Usuario(
                rut=rut,
                nombre_completo=nombre,
                email=email,
                rol_id=rol_id,
                unidad_id=unidad_id,
                establecimiento_id=establecimiento_id,
                calidad_juridica_id=calidad_id,
                categoria_id=categoria_id,
                jefe_directo_id=jefe_id if jefe_id else None, # Permitir nulo
            )
            # Hasheamos la contraseña
            nuevo_usuario.set_password(password)

            # Al crear un nuevo usuario:
            nuevo_usuario.cambio_clave_requerido = forzar_cambio

            # 4. Guardamos en la base de datos
            db.session.add(nuevo_usuario)
            db.session.commit()

            flash('Usuario creado con éxito.', 'success')
            return redirect(url_for('admin_panel'))

        # Si el método es GET, cargamos los datos para los menús desplegables
        roles = Rol.query.order_by(Rol.nombre).all()
        unidades = Unidad.query.order_by(Unidad.nombre).all()
        establecimientos = Establecimiento.query.order_by(Establecimiento.nombre).all()
        calidades = CalidadJuridica.query.order_by(CalidadJuridica.nombre).all()
        categorias = Categoria.query.order_by(Categoria.nombre).all()
        jefes = Usuario.query.filter(Usuario.rol.has(nombre='Jefe')).all()

        return render_template('crear_usuario.html', 
                               roles=roles, 
                               unidades=unidades, 
                               establecimientos=establecimientos, 
                               jefes=jefes,
                               calidades=calidades, 
                               categorias=categorias)
    @app.route('/admin/editar_usuario/<int:id>', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def editar_usuario(id):
        # Usamos get_or_404 para obtener el usuario o devolver un error 404 si no existe
        usuario_a_editar = Usuario.query.get_or_404(id)

        if request.method == 'POST':
            # Actualizamos los datos del usuario con la información del formulario
            usuario_a_editar.rut = request.form.get('rut')
            usuario_a_editar.nombre_completo = request.form.get('nombre_completo')
            usuario_a_editar.email = request.form.get('email')
            usuario_a_editar.rol_id = request.form.get('rol_id')
            usuario_a_editar.unidad_id = request.form.get('unidad_id')
            usuario_a_editar.establecimiento_id = request.form.get('establecimiento_id')
            usuario_a_editar.calidad_juridica_id = request.form.get('calidad_id')
            usuario_a_editar.categoria_id = request.form.get('categoria_id')
            jefe_id = request.form.get('jefe_directo_id')
            usuario_a_editar.jefe_directo_id = jefe_id if jefe_id else None
            forzar_cambio = request.form.get('forzar_cambio_clave') == '1'
            usuario_a_editar.cambio_clave_requerido = forzar_cambio

            # Opcional: Actualizar la contraseña solo si se proporciona una nueva
            password = request.form.get('password')
            if password:
                usuario_a_editar.set_password(password)
            
            # Guardamos los cambios en la base de datos
            db.session.commit()
            flash('Usuario actualizado con éxito.', 'success')
            return redirect(url_for('admin_panel'))

        # Si es GET, mostramos el formulario con los datos actuales del usuario
        roles = Rol.query.order_by(Rol.nombre).all()
        unidades = Unidad.query.order_by(Unidad.nombre).all()
        establecimientos = Establecimiento.query.order_by(Establecimiento.nombre).all()
        calidades = CalidadJuridica.query.order_by(CalidadJuridica.nombre).all()
        categorias = Categoria.query.order_by(Categoria.nombre).all()
        jefes = Usuario.query.filter(Usuario.rol.has(nombre='Jefe')).all()

        return render_template('editar_usuario.html', 
                               usuario=usuario_a_editar,
                               roles=roles, 
                               unidades=unidades, 
                               establecimientos=establecimientos, 
                               calidades=calidades, 
                               categorias=categorias,
                               jefes=jefes)
    
    @app.route('/admin/toggle_activo/<int:id>', methods=['POST'])
    @login_required
    @admin_required
    def toggle_activo(id):
        # Buscamos al usuario
        usuario = Usuario.query.get_or_404(id)
        
        # Invertimos su estado actual
        usuario.activo = not usuario.activo
        
        # Guardamos el cambio
        db.session.commit()
        
        # Enviamos un mensaje de confirmación
        if usuario.activo:
            flash(f'El usuario {usuario.nombre_completo} ha sido activado.', 'success')
        else:
            flash(f'El usuario {usuario.nombre_completo} ha sido desactivado.', 'warning')
            
        return redirect(url_for('admin_panel'))
    
    # --- RUTAS DE USUARIO (FUNCIONARIO / JEFE) ---
    @app.route('/hoja_de_vida')
    @login_required
    @check_password_change
    def mi_hoja_de_vida():
        # Buscamos todas las anotaciones del usuario logueado, ordenadas por fecha de creación descendente.
        anotaciones = Anotacion.query.filter_by(funcionario_id=current_user.id).order_by(Anotacion.fecha_creacion.desc()).all()
        
        return render_template('mi_hoja_de_vida.html', anotaciones=anotaciones)
    
    # --- RUTAS DEL PANEL DE JEFE ---
    @app.route('/jefe/panel')
    @check_password_change
    @login_required
    @jefe_required # Aplicamos nuestro nuevo decorador
    def panel_jefe():
        # Obtenemos el término de búsqueda del formulario
        busqueda = request.args.get('busqueda', '')

        # Empezamos con la consulta base: solo los subordinados del jefe actual
        query = Usuario.query.filter_by(jefe_directo_id=current_user.id)
        if busqueda:
            from sqlalchemy import or_
            query = query.filter(
                or_(
                    Usuario.nombre_completo.ilike(f'%{busqueda}%'),
                    Usuario.rut.ilike(f'%{busqueda}%')
                )
            )
        # Buscamos a todos los usuarios cuyo jefe_directo_id sea el id del usuario actual.
        # Esto nos da la lista de subordinados.
        subordinados = query.order_by(Usuario.nombre_completo).all()
        
        return render_template('panel_jefe.html', subordinados=subordinados, busqueda=busqueda)
    
    @app.route('/jefe/crear_anotacion/<int:funcionario_id>', methods=['GET', 'POST'])
    @login_required
    @jefe_required
    def crear_anotacion(funcionario_id):
        # Obtenemos los datos del funcionario que recibirá la anotación
        funcionario = Usuario.query.get_or_404(funcionario_id)

        if request.method == 'POST':
            # Recolectamos los datos del formulario
            tipo = request.form.get('tipo')
            subfactor_id = request.form.get('subfactor_id')
            motivo = request.form.get('motivo_jefe')

            # Creamos la nueva anotación
            nueva_anotacion = Anotacion(
                tipo=tipo,
                motivo_jefe=motivo,
                fecha_creacion=date.today(), # Usamos la fecha actual
                funcionario_id=funcionario.id, # El ID del funcionario de la URL
                jefe_id=current_user.id, # El ID del jefe que está logueado
                subfactor_id=subfactor_id
            )

            # Guardamos en la base de datos
            db.session.add(nueva_anotacion)
            db.session.commit()

            flash(f'Anotación creada con éxito para {funcionario.nombre_completo}.', 'success')
            return redirect(url_for('panel_jefe'))

        # Si es GET, cargamos los datos para los menús desplegables
        factores = Factor.query.order_by(Factor.id).all()
        subfactores = SubFactor.query.order_by(SubFactor.id).all()

        return render_template('crear_anotacion.html', 
                               funcionario=funcionario, 
                               factores=factores, 
                               subfactores=subfactores)
    
    @app.route('/jefe/hoja_de_vida/<int:funcionario_id>')
    @login_required
    @jefe_required
    def ver_hoja_de_vida_funcionario(funcionario_id):
        funcionario = Usuario.query.get_or_404(funcionario_id)

        # Seguridad: Un jefe solo puede ver a sus subordinados directos (Admin puede ver a todos).
        if funcionario.jefe_directo_id != current_user.id and current_user.rol.nombre != 'Admin':
            abort(403)

        # Buscamos todas las anotaciones del funcionario, ordenadas por fecha.
        anotaciones = Anotacion.query.filter_by(funcionario_id=funcionario.id).order_by(Anotacion.fecha_creacion.desc()).all()

        return render_template('hoja_de_vida_funcionario.html', 
                               funcionario=funcionario, 
                               anotaciones=anotaciones)
    
    @app.route('/anotacion/ver/<int:folio>', methods=['GET', 'POST'])
    @login_required
    def ver_anotacion(folio):
        # Buscamos la anotación por su folio
        anotacion = Anotacion.query.get_or_404(folio)

        # --- Medida de seguridad mejorada ---
        # Verificamos si el usuario actual es el funcionario de la anotación,
        # su jefe directo, o un administrador.
        funcionario_de_anotacion = anotacion.funcionario
        es_el_funcionario = (current_user.id == funcionario_de_anotacion.id)
        es_el_jefe_directo = (current_user.id == funcionario_de_anotacion.jefe_directo_id)
        es_admin = (current_user.rol.nombre == 'Admin')

        if not (es_el_funcionario or es_el_jefe_directo or es_admin):
            abort(403) # Si no cumple ninguna condición, prohibimos el acceso.

        if request.method == 'POST':
            # Verificamos que el checkbox 'tomo_conocimiento' haya sido marcado
            if 'tomo_conocimiento' in request.form:
                # Actualizamos el estado de la anotación
                anotacion.estado = 'Aceptada'
                anotacion.fecha_aceptacion = datetime.now() # Guardamos fecha y hora
                
                # Guardamos las observaciones del funcionario (si las hay)
                observaciones = request.form.get('observacion_funcionario')
                anotacion.observacion_funcionario = observaciones if observaciones else "Sin observaciones."

                # Guardamos los cambios en la base de datos
                db.session.commit()

                flash('Has confirmado la lectura de la anotación.', 'success')
                return redirect(url_for('mi_hoja_de_vida'))
            else:
                flash('Debes marcar la casilla "Tomo conocimiento" para confirmar.', 'warning')
        
        # Si es GET, simplemente mostramos la página con los detalles
        return render_template('ver_anotacion.html', anotacion=anotacion)
    
    @app.route('/cambiar_clave', methods=['GET', 'POST'])
    @login_required
    def cambiar_clave():
        # Si el usuario no necesita cambiar la clave, lo sacamos de aquí
        if not current_user.cambio_clave_requerido:
            return redirect(url_for('index')) # O a su panel correspondiente

        if request.method == 'POST':
            nueva_password = request.form.get('nueva_password')
            # (Aquí podrías añadir validación de seguridad del lado del servidor también)

            current_user.set_password(nueva_password)
            current_user.cambio_clave_requerido = False # ¡Muy importante!
            db.session.commit()

            logout_user() # Lo deslogueamos para que inicie sesión con su nueva clave
            flash('Contraseña actualizada exitosamente. Por favor, inicia sesión de nuevo.', 'success')
            return redirect(url_for('login'))

        return render_template('cambiar_clave.html')
    
    @app.route('/solicitar-reseteo', methods=['GET', 'POST'])
    def solicitar_reseteo():
        if request.method == 'POST':
            email = request.form.get('email')
            usuario = Usuario.query.filter_by(email=email).first()

            if usuario:
                token = secrets.token_hex(16)
                expiracion = datetime.utcnow() + timedelta(hours=1)

                # Guardar token y expiración en el objeto usuario
                usuario.reset_token = token
                usuario.reset_token_expiracion = expiracion
                db.session.commit()

                # Enviar correo
                enviar_correo_reseteo(usuario, token)

            # Por seguridad, mostramos el mismo mensaje exista o no el correo
            flash('Si tu correo está en nuestro sistema, recibirás un enlace para restablecer tu contraseña.', 'info')
            return redirect(url_for('login'))

        return render_template('solicitar_reseteo.html')
    
    @app.route('/resetear-clave/<token>', methods=['GET', 'POST'])
    def resetear_clave(token):
        # Buscamos al usuario por el token y verificamos que no haya expirado
        usuario = Usuario.query.filter_by(reset_token=token).first()

        if not usuario or usuario.reset_token_expiracion < datetime.utcnow():
            flash('El enlace de reseteo es inválido o ha expirado.', 'danger')
            return redirect(url_for('solicitar_reseteo'))

        if request.method == 'POST':
            nueva_password = request.form.get('nueva_password')
            usuario.set_password(nueva_password)

            # Invalidamos el token para que no se pueda reusar
            usuario.reset_token = None
            usuario.reset_token_expiracion = None
            db.session.commit()

            flash('Tu contraseña ha sido actualizada. Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))

        return render_template('resetear_clave.html')
    
    return app

def enviar_correo_reseteo(usuario, token):
    remitente = os.getenv("EMAIL_USUARIO")
    contrasena = os.getenv("EMAIL_CONTRASENA")

    if not remitente or not contrasena:
        print("ERROR: Asegúrate de que EMAIL_USUARIO y EMAIL_CONTRASENA están en tu archivo .env")
        return

    msg = MIMEMultipart()
    msg['Subject'] = 'Restablecimiento de Contraseña - Sistema Hoja de Vida'
    msg['From'] = f"Sistema Hoja de Vida <{remitente}>"
    msg['To'] = usuario.email # Adaptado a nuestro objeto Usuario

    url_reseteo = url_for('resetear_clave', token=token, _external=True)
    cuerpo_html = f"""
    <p>Hola {usuario.nombre_completo},</p>
    <p>Hemos recibido una solicitud para restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:</p>
    <p><a href="{url_reseteo}" style="padding: 10px 15px; background-color: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">Restablecer mi contraseña</a></p>
    <p>Si no solicitaste esto, puedes ignorar este correo.</p>
    <p>El enlace expirará en 1 hora.</p>
    """
    msg.attach(MIMEText(cuerpo_html, 'html'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(remitente, contrasena)
            server.send_message(msg)
            print(f"Correo de reseteo enviado exitosamente a {usuario.email}")
    except Exception as e:
        print(f"Error al enviar correo de reseteo: {e}")

# --- USER LOADER ---
# Esta función es crucial. Flask-Login la usa para recargar el objeto de usuario 
# desde el ID de usuario almacenado en la sesión.
@login_manager.user_loader
def load_user(user_id):
    # Simplemente le pide a SQLAlchemy que encuentre el usuario por su ID.
    return Usuario.query.get(int(user_id))

# Creamos la aplicación para poder ejecutarla
app = create_app()

# --- INICIO: Decorador para evitar caché ---
@app.after_request
def add_header(response):
    """
    Añade cabeceras para evitar que el navegador guarde en caché las páginas.
    Esto soluciona el problema de los mensajes flash que reaparecen al usar el botón "atrás".
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response
# --- FIN: Decorador para evitar caché ---

# Punto de entrada para ejecutar la aplicación
if __name__ == '__main__':
    # El modo debug se recarga automáticamente cuando guardas cambios
    app.run(debug=True)