# app.py

import os
from dotenv import load_dotenv
from flask import Flask
# Importamos las extensiones y los modelos que usaremos
from flask_login import LoginManager
from models import db, Usuario, Rol, Establecimiento, Unidad, CalidadJuridica, Categoria
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
    def mi_hoja_de_vida():
        # En el futuro, aquí consultaremos las anotaciones del usuario
        # anotaciones = Anotacion.query.filter_by(funcionario_id=current_user.id).all()
        return render_template('mi_hoja_de_vida.html')
    
    # --- RUTAS DEL PANEL DE JEFE ---
    @app.route('/jefe/panel')
    @login_required
    @jefe_required # Aplicamos nuestro nuevo decorador
    def panel_jefe():
        # Buscamos a todos los usuarios cuyo jefe_directo_id sea el id del usuario actual.
        # Esto nos da la lista de subordinados.
        subordinados = Usuario.query.filter_by(jefe_directo_id=current_user.id).order_by(Usuario.nombre_completo).all()
        
        return render_template('panel_jefe.html', subordinados=subordinados)
    
    return app

# --- USER LOADER ---
# Esta función es crucial. Flask-Login la usa para recargar el objeto de usuario 
# desde el ID de usuario almacenado en la sesión.
@login_manager.user_loader
def load_user(user_id):
    # Simplemente le pide a SQLAlchemy que encuentre el usuario por su ID.
    return Usuario.query.get(int(user_id))

# Creamos la aplicación para poder ejecutarla
app = create_app()

# Punto de entrada para ejecutar la aplicación
if __name__ == '__main__':
    # El modo debug se recarga automáticamente cuando guardas cambios
    app.run(debug=True)