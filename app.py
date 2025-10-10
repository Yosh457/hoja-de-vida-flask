# app.py

import os
from dotenv import load_dotenv
from flask import Flask
# Importamos las extensiones y los modelos que usaremos
from flask_login import LoginManager
from models import db, Usuario
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
        # Si el usuario ya está autenticado, lo redirigimos al menú
        if current_user.is_authenticated:
            return redirect(url_for('menu'))

        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Buscamos al usuario por su email en la base de datos
            usuario = Usuario.query.filter_by(email=email).first()

            # Verificamos si el usuario existe y si la contraseña es correcta
            if not usuario or not usuario.check_password(password):
                flash('Email o contraseña incorrectos. Por favor, inténtalo de nuevo.', 'danger')
                return redirect(url_for('login'))
            
            # Si todo es correcto, iniciamos la sesión del usuario
            login_user(usuario)
            flash('¡Has iniciado sesión correctamente!', 'success')
            return redirect(url_for('menu'))

        # Si el método es GET, simplemente mostramos la página de login
        return render_template('login.html')

    @app.route('/logout')
    @login_required # Solo un usuario logueado puede desloguearse
    def logout():
        logout_user()
        flash('Has cerrado la sesión.', 'success')
        return redirect(url_for('login'))
        
    # --- RUTA PROTEGIDA DE EJEMPLO ---

    @app.route('/menu')
    @login_required # Esta es la magia: solo usuarios logueados pueden ver esta página
    def menu():
        return render_template('menu.html')
    
    # --- RUTAS DEL PANEL DE ADMINISTRACIÓN ---
    @app.route('/admin/panel')
    @login_required
    @admin_required # ¡Aplicamos nuestro decorador personalizado!
    def admin_panel():
        # Obtenemos todos los usuarios y los ordenamos por ID
        usuarios = Usuario.query.order_by(Usuario.id).all()
        return render_template('admin_panel.html', usuarios=usuarios)
    
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