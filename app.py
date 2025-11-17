# app.py (NUEVA VERSIÓN REFACTORIZADA)

import os
from dotenv import load_dotenv
from flask import Flask, redirect, url_for, Response, flash
from flask_wtf.csrf import CSRFError

# Importamos las instancias de nuestros archivos
from models import db, Usuario
from extensions import login_manager, csrf

# Importamos las funciones de ayuda que necesita create_app
from utils import registrar_log, check_password_change

def create_app():
    """Crea y configura la aplicación Flask."""
    app = Flask(__name__)
    app.jinja_env.add_extension('jinja2.ext.do')
    load_dotenv()

    # --- CONFIGURACIÓN DE LA APLICACIÓN ---
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    db_user = 'root'
    db_password = os.getenv('MYSQL_PASSWORD')
    db_name = 'hoja_de_vida_db'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@localhost/{db_name}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # --- INICIALIZACIÓN DE EXTENSIONES ---
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Configuración de Flask-Login
    login_manager.login_view = 'auth.login' # ¡Apunta al Blueprint!
    login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'
    login_manager.login_message_category = 'warning'

    # --- REGISTRO DE BLUEPRINTS ---
    # Importamos los blueprints *dentro* de la función
    from blueprints.auth import auth_bp 
    app.register_blueprint(auth_bp)

    from blueprints.admin import admin_bp
    app.register_blueprint(admin_bp)

    from blueprints.libro import libro_bp
    app.register_blueprint(libro_bp)

    from blueprints.jefa_salud import jefa_salud_bp
    app.register_blueprint(jefa_salud_bp)

    from blueprints.recinto import recinto_bp
    app.register_blueprint(recinto_bp)

    from blueprints.unidad import unidad_bp
    app.register_blueprint(unidad_bp)

    # --- RUTAS GLOBALES (Como el index) ---
    @app.route('/')
    def index():
        return redirect(url_for('auth.login')) # Apunta al Blueprint

    # --- MANEJADORES DE ERRORES ---
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash('Tu sesión ha expirado o la solicitud no es válida. Por favor, ingresa nuevamente.', 'warning')
        return redirect(url_for('auth.login'))
    
    return app

# --- USER LOADER (Fuera de create_app, como lo tenías) ---
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# --- PUNTO DE ENTRADA ---
app = create_app()

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

if __name__ == '__main__':
    app.run(debug=True)