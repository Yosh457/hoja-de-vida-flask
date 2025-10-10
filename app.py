# app.py

import os
from dotenv import load_dotenv
from flask import Flask
# ¡Importante! Importamos 'db' desde nuestro nuevo archivo models.py
from models import db

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

    # --- RUTAS (BLUEPRINTS) ---
    # (Aquí registraremos nuestras rutas más adelante)

    # --- Ruta de prueba para verificar que todo funciona ---
    @app.route('/')
    def index():
        return "¡Hola Mundo! La aplicación Flask está funcionando y conectada con los modelos."

    return app

# Creamos la aplicación para poder ejecutarla
app = create_app()

# Punto de entrada para ejecutar la aplicación
if __name__ == '__main__':
    # El modo debug se recarga automáticamente cuando guardas cambios
    app.run(debug=True)