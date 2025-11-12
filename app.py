# app.py

import os
from dotenv import load_dotenv
from flask import Flask
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
# Importamos las extensiones y los modelos que usaremos
from models import db, Usuario, Rol, Establecimiento, Unidad, CalidadJuridica, Categoria, Anotacion, Factor, SubFactor, Log
from datetime import date, datetime, timedelta
from flask import render_template, redirect, url_for, flash, request, jsonify, abort, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from functools import wraps
from weasyprint import HTML
from sqlalchemy import or_
from flask_wtf.csrf import CSRFProtect, CSRFError

# Inicializamos el gestor de logins
login_manager = LoginManager()

# Crea la instancia globalmente o antes de create_app
csrf = CSRFProtect()

# --- DECORADOR DE ROL ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Si el usuario no es admin, mostramos un error de "no autorizado"
        if not current_user.is_authenticated or current_user.rol.nombre != 'Admin':
            abort(403) # Error 403: Forbidden
        return f(*args, **kwargs)
    return decorated_function

# --- DECORADOR DE ROL JEFA SALUD ---
def jefa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Permite el acceso si el rol es 'Jefa Salud' O 'Admin'
        if not current_user.is_authenticated or (current_user.rol.nombre not in ['Admin', 'Jefa Salud']):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- DECORADOR DE ROL ENCARGADO DE UNIDAD ---
def encargado_unidad_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Permite Admin, Jefa Salud, o Encargado de Unidad
        if not current_user.is_authenticated or (current_user.rol.nombre not in ['Admin', 'Jefa Salud', 'Encargado de Unidad']):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- DECORADOR DE ROL ENCARGADO DE RECINTO ---
def encargado_recinto_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Permite Admin, Jefa Salud, o Encargado de Recinto
        if not current_user.is_authenticated or (current_user.rol.nombre not in ['Admin', 'Jefa Salud', 'Encargado de Recinto']):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def check_password_change(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.cambio_clave_requerido:
            return redirect(url_for('cambiar_clave'))
        return f(*args, **kwargs)
    return decorated_function

def es_superior_jerarquico(usuario_actual, funcionario_a_ver):
    """
    Verifica si el usuario_actual es superior jerárquico (directo o indirecto) 
    del funcionario_a_ver.
    """
    # Si el funcionario a ver no tiene jefe, nadie puede ser su superior.
    if not funcionario_a_ver.jefe_directo:
        return False
    
    jefe_actual = funcionario_a_ver.jefe_directo
    # Recorremos la cadena de mando hacia arriba
    while jefe_actual:
        # Si encontramos al usuario_actual en la cadena, es un superior.
        if jefe_actual.id == usuario_actual.id:
            return True
        # Pasamos al siguiente jefe en la jerarquía
        jefe_actual = jefe_actual.jefe_directo
    
    # Si llegamos al final sin encontrarlo, no es un superior.
    return False

def create_app():
    """Crea y configura la aplicación Flask."""
    # Inicializamos la aplicación Flask
    app = Flask(__name__)
    # Habilitamos la extensión 'do' en el entorno de Jinja2.
    app.jinja_env.add_extension('jinja2.ext.do')
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

    # Inicializa la protección CSRF para la app
    csrf.init_app(app)
    
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
            elif current_user.rol.nombre == 'Jefa Salud':
                return redirect(url_for('panel_jefa_salud'))
            elif current_user.rol.nombre == 'Encargado de Recinto': # <-- NUEVO
                return redirect(url_for('panel_encargado_recinto'))
            elif current_user.rol.nombre == 'Encargado de Unidad': # <-- RENOMBRADO
                return redirect(url_for('panel_encargado_unidad'))
            else: # Funcionario
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
            # --- ¡REGISTRAR LOG! ---
            registrar_log(accion="Inicio de Sesión", detalles=f"Usuario {usuario.nombre_completo} (ID: {usuario.id}) inició sesión.")
            db.session.commit() # Guardamos el log
            # ------------------------
            flash('¡Has iniciado sesión correctamente!', 'success')
            # --- LÓGICA DE REDIRECCIÓN POR ROL ---
            if usuario.rol.nombre == 'Admin':
                return redirect(url_for('admin_panel'))
            elif usuario.rol.nombre == 'Jefa Salud':
                return redirect(url_for('panel_jefa_salud'))
            elif usuario.rol.nombre == 'Encargado de Recinto': # <-- NUEVO
                return redirect(url_for('panel_encargado_recinto'))
            elif usuario.rol.nombre == 'Encargado de Unidad': # <-- RENOMBRADO
                return redirect(url_for('panel_encargado_unidad'))
            else: # Funcionario
                return redirect(url_for('mi_hoja_de_vida'))

        # Si el método es GET, simplemente mostramos la página de login
        return render_template('login.html')

    @app.route('/logout')
    @login_required # Solo un usuario logueado puede desloguearse
    def logout():
        # --- ¡REGISTRAR LOG! ---
        # Lo hacemos antes para aún tener acceso a current_user
        registrar_log(accion="Cierre de Sesión", detalles=f"Usuario {current_user.nombre_completo} (ID: {current_user.id}) cerró sesión.")
        db.session.commit() # Guardamos el log
        # ------------------------
        logout_user()
        flash('Has cerrado la sesión.', 'success')
        return redirect(url_for('login'))
    
    # --- RUTAS DEL PANEL DE ADMINISTRACIÓN ---
    @app.route('/admin/panel')
    @login_required
    @check_password_change
    @admin_required # ¡Aplicamos nuestro decorador personalizado!
    def admin_panel():
        page = request.args.get('page', 1, type=int)
        
        # --- INICIO: Lógica de Filtros Mejorada ---
        busqueda = request.args.get('busqueda', '')
        rol_filtro = request.args.get('rol_filtro', '')
        # ¡NUEVO! Leemos el filtro de unidad
        unidad_filtro = request.args.get('unidad_filtro', '')
        estado_filtro = request.args.get('estado_filtro', '')

        # Empezamos con la consulta base de todos los usuarios
        query = Usuario.query

        # Aplicamos los filtros dinámicamente
        if busqueda:
            query = query.filter(
                or_(
                    Usuario.nombre_completo.ilike(f'%{busqueda}%'),
                    Usuario.email.ilike(f'%{busqueda}%')
                )
            )
        
        if rol_filtro:
            query = query.filter(Usuario.rol_id == rol_filtro)

        # ¡NUEVO! Aplicamos el filtro de unidad si existe
        if unidad_filtro:
            query = query.filter(Usuario.unidad_id == unidad_filtro)

        if estado_filtro:
            if estado_filtro == 'activo':
                query = query.filter(Usuario.activo == True)
            elif estado_filtro == 'inactivo':
                query = query.filter(Usuario.activo == False)
        
        # Obtenemos las listas para poblar los menús desplegables de los filtros
        roles_para_filtro = Rol.query.order_by(Rol.nombre).all()
        # ¡NUEVO! Obtenemos las unidades
        unidades_para_filtro = Unidad.query.order_by(Unidad.nombre).all()
        # --- FIN: Lógica de Filtros ---

        pagination = query.order_by(Usuario.id).paginate(
            page=page, per_page=10, error_out=False
        )
        
        # Pasamos todas las variables de filtro a la plantilla
        return render_template('admin_panel.html', 
                            pagination=pagination,
                            roles_para_filtro=roles_para_filtro,
                            unidades_para_filtro=unidades_para_filtro, # ¡NUEVO!
                            busqueda=busqueda,
                            rol_filtro=rol_filtro,
                            unidad_filtro=unidad_filtro, # ¡NUEVO!
                            estado_filtro=estado_filtro)
    
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
        jefes = Usuario.query.join(Usuario.rol).filter(
            or_(
                Rol.nombre == 'Jefa Salud',
                Rol.nombre == 'Encargado de Recinto',
                Rol.nombre == 'Encargado de Unidad'
            )
        ).order_by(Usuario.nombre_completo).all()

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
        jefes = Usuario.query.join(Usuario.rol).filter(
            or_(
                Rol.nombre == 'Jefa Salud',
                Rol.nombre == 'Encargado de Recinto',
                Rol.nombre == 'Encargado de Unidad'
            )
        ).order_by(Usuario.nombre_completo).all()

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
        
        # --- ¡REGISTRAR LOG! ---
        accion_realizada = "Activación" if usuario.activo else "Desactivación"
        detalles_log = (f"Admin {current_user.nombre_completo} (ID: {current_user.id}) realizó "
                    f"{accion_realizada} del usuario {usuario.nombre_completo} (ID: {usuario.id}).")
        registrar_log(accion=f"{accion_realizada} de Usuario", detalles=detalles_log)
        # ------------------------
        # Guardamos el cambio (usuario y log)
        db.session.commit()
        
        # Enviamos un mensaje de confirmación
        if usuario.activo:
            flash(f'El usuario {usuario.nombre_completo} ha sido activado.', 'success')
        else:
            flash(f'El usuario {usuario.nombre_completo} ha sido desactivado.', 'warning')
            
        return redirect(url_for('admin_panel'))
    
    @app.route('/admin/ver_logs')
    @login_required
    @check_password_change
    @admin_required
    def ver_logs():
        page = request.args.get('page', 1, type=int)
        
        # --- Lógica de Filtros para Logs ---
        usuario_filtro_id = request.args.get('usuario_id', '')
        accion_filtro = request.args.get('accion', '') # Podríamos añadir filtro por acción si quisiéramos

        # Consulta base, ordenada por fecha descendente
        query = Log.query.order_by(Log.timestamp.desc())

        # Aplicar filtros
        if usuario_filtro_id:
            query = query.filter(Log.usuario_id == usuario_filtro_id)
        # if accion_filtro: # Ejemplo si quisiéramos filtrar por acción
        #     query = query.filter(Log.accion.ilike(f'%{accion_filtro}%'))
            
        # Paginamos los resultados
        logs_pagination = query.paginate(page=page, per_page=15, error_out=False) # Mostramos 15 logs por página

        # Obtenemos todos los usuarios para el menú desplegable del filtro
        todos_los_usuarios = Usuario.query.order_by(Usuario.nombre_completo).all()
        
        # Creamos un diccionario con los filtros actuales para pasarlo a la plantilla
        filtros_actuales = {
            'usuario_id': usuario_filtro_id,
            'accion': accion_filtro
        }

        return render_template('ver_logs.html',
                            pagination=logs_pagination,
                            todos_los_usuarios=todos_los_usuarios,
                            filtros=filtros_actuales)

    # --- RUTAS DE USUARIO (FUNCIONARIO / JEFE) ---
    @app.route('/hoja_de_vida')
    @login_required
    @check_password_change
    def mi_hoja_de_vida():
        page = request.args.get('page', 1, type=int)
        
        # --- Lógica de Filtros para Anotaciones ---
        tipo_filtro = request.args.get('tipo_filtro', '')
        factor_filtro = request.args.get('factor_filtro', '')
        subfactor_filtro = request.args.get('subfactor_filtro', '')
        fecha_inicio_str = request.args.get('fecha_inicio', '')
        fecha_fin_str = request.args.get('fecha_fin', '')

        # Consulta base
        query = Anotacion.query.filter_by(funcionario_id=current_user.id)

        # Filtros generales (se aplican a pendientes y historial)
        if tipo_filtro:
            query = query.filter(Anotacion.tipo == tipo_filtro)
        if factor_filtro:
            query = query.join(Anotacion.subfactor).filter(SubFactor.factor_id == factor_filtro)
        if subfactor_filtro:
            query = query.filter(Anotacion.subfactor_id == subfactor_filtro)
        
        # Separamos pendientes (sin paginación, siempre visibles)
        anotaciones_pendientes = query.filter(Anotacion.estado == 'Pendiente').order_by(Anotacion.folio.desc()).all()

        # Consulta específica para el historial paginado
        historial_query = query.filter(Anotacion.estado == 'Aceptada')
        
        # Aplicar filtros de fecha SOLO al historial
        try:
            if fecha_inicio_str:
                fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
                historial_query = historial_query.filter(Anotacion.fecha_creacion >= fecha_inicio)
            if fecha_fin_str:
                fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
                historial_query = historial_query.filter(Anotacion.fecha_creacion <= fecha_fin)
        except ValueError:
            flash("Formato de fecha inválido. Por favor, usa YYYY-MM-DD.", "danger")
            return redirect(request.path) 

        # Paginamos el historial ya filtrado
        historial_pagination = historial_query.order_by(Anotacion.fecha_creacion.desc(), Anotacion.folio.desc()).paginate(
            page=page, per_page=5, error_out=False
        )
        
        # Datos para los filtros
        factores_para_filtro = [{'id': f.id, 'nombre': f.nombre} for f in Factor.query.order_by(Factor.nombre).all()]
        subfactores_para_filtro = [{'id': sf.id, 'nombre': sf.nombre, 'factor_id': sf.factor_id} for sf in SubFactor.query.all()]

        return render_template('mi_hoja_de_vida.html', 
                            anotaciones_pendientes=anotaciones_pendientes,
                            historial_pagination=historial_pagination,
                            factores_para_filtro=factores_para_filtro,
                            subfactores_para_filtro=subfactores_para_filtro,
                            tipo_filtro=tipo_filtro,
                            factor_filtro=factor_filtro,
                            subfactor_filtro=subfactor_filtro,
                            fecha_inicio=fecha_inicio_str,
                            fecha_fin=fecha_fin_str)

    # --- RUTA NUEVA: PANEL ENCARGADO DE RECINTO ---
    @app.route('/recinto/panel')
    @login_required
    @check_password_change
    @encargado_recinto_required # Usamos el nuevo decorador
    def panel_encargado_recinto():
        page = request.args.get('page', 1, type=int)
        busqueda = request.args.get('busqueda', '')

        # Buscamos a los 'Encargado de Unidad' que reportan a este 'Encargado de Recinto'
        query = Usuario.query.filter(
            Usuario.jefe_directo_id == current_user.id,
            Usuario.rol.has(nombre='Encargado de Unidad')
        )

        if busqueda:
            query = query.filter(
                or_(
                    Usuario.nombre_completo.ilike(f'%{busqueda}%'),
                    Usuario.rut.ilike(f'%{busqueda}%')
                )
            )

        encargados_unidad = query.order_by(Usuario.nombre_completo).paginate(
            page=page, per_page=10, error_out=False
        )
        
        # Usaremos una plantilla nueva
        return render_template('panel_encargado_recinto.html',
                               pagination=encargados_unidad,
                               busqueda=busqueda)
    
    # --- RUTAS DEL PANEL DE ENCARGADO DE UNIDAD ---
    @app.route('/encargado_unidad/panel')
    @check_password_change
    @login_required
    @encargado_unidad_required # Aplicamos nuestro nuevo decorador
    def panel_encargado_unidad():
        page = request.args.get('page', 1, type=int)
        # Obtenemos el término de búsqueda del formulario
        busqueda = request.args.get('busqueda', '')

        # Empezamos con la consulta base: solo los subordinados del jefe actual
        query = Usuario.query.filter_by(jefe_directo_id=current_user.id)
        if busqueda:
            query = query.filter(
                or_(
                    Usuario.nombre_completo.ilike(f'%{busqueda}%'),
                    Usuario.rut.ilike(f'%{busqueda}%')
                )
            )
        # Filtramos solo por rol "Funcionario"
        query = query.filter(Usuario.rol.has(nombre='Funcionario'))

        pagination = query.order_by(Usuario.nombre_completo).paginate(
            page=page, per_page=10, error_out=False
        )
        return render_template('panel_encargado_unidad.html', 
                               pagination=pagination, 
                               busqueda=busqueda)
    
    @app.route('/crear_anotacion/<int:funcionario_id>', methods=['GET', 'POST'])
    @login_required
    @check_password_change 
    # Quitamos el decorador @jefe_required
    def crear_anotacion(funcionario_id):
        funcionario = Usuario.query.get_or_404(funcionario_id)

        # --- NUEVA LÓGICA DE PERMISOS ---
        puede_anotar = False
        
        # Regla 1: Jefa Salud anota a Encargado de Recinto o Encargado de Unidad
        if (current_user.rol.nombre == 'Jefa Salud' and
            funcionario.rol.nombre in ['Encargado de Recinto', 'Encargado de Unidad'] and
            funcionario.jefe_directo_id == current_user.id):
            puede_anotar = True

        # Regla 2: Encargado de Recinto anota a Encargado de Unidad (¡NUEVA REGLA!)
        elif (current_user.rol.nombre == 'Encargado de Recinto' and
              funcionario.rol.nombre == 'Encargado de Unidad' and
              funcionario.jefe_directo_id == current_user.id):
            puede_anotar = True

        # Regla 3: Encargado de Unidad anota a Funcionario
        elif (current_user.rol.nombre == 'Encargado de Unidad' and
              funcionario.rol.nombre == 'Funcionario' and
              funcionario.jefe_directo_id == current_user.id):
            puede_anotar = True
            
        # Regla 4: Admin siempre puede
        elif current_user.rol.nombre == 'Admin':
            puede_anotar = True

        if not puede_anotar:
            flash('No tienes permisos para crear anotaciones a este usuario.', 'danger')
            # Redirigir al panel correspondiente
            if current_user.rol.nombre == 'Jefa Salud':
                return redirect(url_for('panel_jefa_salud'))
            elif current_user.rol.nombre == 'Encargado de Recinto':
                return redirect(url_for('panel_encargado_recinto'))
            elif current_user.rol.nombre == 'Encargado de Unidad':
                return redirect(url_for('panel_encargado_unidad'))
            else:
                return redirect(url_for('mi_hoja_de_vida'))
        # --- FIN LÓGICA DE PERMISOS ---

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
            # Flush para obtener el folio asignado antes del commit final
            db.session.flush()

            # --- ¡REGISTRAR LOG! ---
            detalles_log = (f"Jefe {current_user.nombre_completo} (ID: {current_user.id}) creó anotación "
                        f"{nueva_anotacion.tipo} (Folio: {nueva_anotacion.folio}) para "
                        f"{funcionario.nombre_completo} (ID: {funcionario.id}). "
                        f"Factor: {nueva_anotacion.subfactor.factor.nombre}, "
                        f"SubFactor: {nueva_anotacion.subfactor.nombre}.")
            registrar_log(accion="Creación de Anotación", detalles=detalles_log)
            # ------------------------
            # Guardamos la anotación y el log juntos
            db.session.commit()

            # --- Enviamos el correo de notificación ---
            enviar_correo_notificacion_anotacion(nueva_anotacion)

            flash(f'Anotación creada con éxito para {funcionario.nombre_completo}.', 'success')

            # --- Redirección Condicional por Rol Actualizada ---
            if current_user.rol.nombre == 'Jefa Salud':
                return redirect(url_for('panel_jefa_salud'))
            elif current_user.rol.nombre == 'Encargado de Recinto': # <-- AÑADIDO
                return redirect(url_for('panel_encargado_recinto'))
            elif current_user.rol.nombre == 'Encargado de Unidad':
                return redirect(url_for('panel_encargado_unidad'))
            else: 
                return redirect(url_for('admin_panel')) # Fallback para Admin
            # --- Fin Redirección Condicional ---
            
        # Si es GET, cargamos los datos para los menús desplegables
        factores = Factor.query.order_by(Factor.id).all()
        subfactores = SubFactor.query.order_by(SubFactor.id).all()

        return render_template('crear_anotacion.html', 
                               funcionario=funcionario, 
                               factores=factores, 
                               subfactores=subfactores)
    
    @app.route('/hoja_de_vida/<int:funcionario_id>')
    @login_required
    @check_password_change
    # Quitamos el decorador @jefe_required
    def ver_hoja_de_vida_funcionario(funcionario_id):
        page = request.args.get('page', 1, type=int)
        funcionario = Usuario.query.get_or_404(funcionario_id)
        
        # --- Nueva Verificación de Permisos ---
        es_admin = (current_user.rol.nombre == 'Admin')
        # Usamos nuestra nueva función de ayuda
        es_superior = es_superior_jerarquico(current_user, funcionario)

        # Permitir acceso si es Admin O es un superior jerárquico
        if not (es_admin or es_superior):
            abort(403)
        # --- Fin Verificación ---

        # --- Lógica de Filtros para Anotaciones ---
        tipo_filtro = request.args.get('tipo_filtro', '')
        factor_filtro = request.args.get('factor_filtro', '')
        subfactor_filtro = request.args.get('subfactor_filtro', '')
        fecha_inicio_str = request.args.get('fecha_inicio', '')
        fecha_fin_str = request.args.get('fecha_fin', '')
        
        # Consulta base
        query = Anotacion.query.filter_by(funcionario_id=funcionario.id)
        
        # Filtros generales
        if tipo_filtro:
            query = query.filter(Anotacion.tipo == tipo_filtro)
        if factor_filtro:
            query = query.join(Anotacion.subfactor).filter(SubFactor.factor_id == factor_filtro)
        if subfactor_filtro:
            query = query.filter(Anotacion.subfactor_id == subfactor_filtro)

        # Separamos pendientes
        anotaciones_pendientes = query.filter(Anotacion.estado == 'Pendiente').order_by(Anotacion.folio.desc()).all()

        # Consulta específica para historial
        historial_query = query.filter(Anotacion.estado == 'Aceptada')

        # Aplicar filtros de fecha SOLO al historial
        try:
            if fecha_inicio_str:
                fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
                historial_query = historial_query.filter(Anotacion.fecha_creacion >= fecha_inicio)
            if fecha_fin_str:
                fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
                historial_query = historial_query.filter(Anotacion.fecha_creacion <= fecha_fin)
        except ValueError:
            flash("Formato de fecha inválido. Por favor, usa YYYY-MM-DD.", "danger")
            return redirect(request.path) 

        # Paginamos historial
        historial_pagination = historial_query.order_by(Anotacion.fecha_creacion.desc(), Anotacion.folio.desc()).paginate(
            page=page, per_page=5, error_out=False
        )
        
        # Datos para los filtros
        factores_para_filtro = [{'id': f.id, 'nombre': f.nombre} for f in Factor.query.order_by(Factor.nombre).all()]
        subfactores_para_filtro = [{'id': sf.id, 'nombre': sf.nombre, 'factor_id': sf.factor_id} for sf in SubFactor.query.all()]
        
        return render_template('hoja_de_vida_funcionario.html', 
                            funcionario=funcionario, 
                            anotaciones_pendientes=anotaciones_pendientes,
                            historial_pagination=historial_pagination,
                            factores_para_filtro=factores_para_filtro,
                            subfactores_para_filtro=subfactores_para_filtro,
                            tipo_filtro=tipo_filtro,
                            factor_filtro=factor_filtro,
                            subfactor_filtro=subfactor_filtro,
                            fecha_inicio=fecha_inicio_str,
                            fecha_fin=fecha_fin_str)
    # app.py (dentro de create_app)

    # --- RUTAS DEL PANEL JEFA DE SALUD ---
    @app.route('/jefa/panel')
    @login_required
    @check_password_change
    @jefa_required
    def panel_jefa_salud():
        page = request.args.get('page', 1, type=int)
        busqueda = request.args.get('busqueda', '')

        # Buscamos a todos los que reportan a la Jefa de Salud
        # Y que tengan CUALQUIERA de los dos roles de encargado
        query = Usuario.query.filter(
            Usuario.jefe_directo_id == current_user.id,
            Usuario.rol.has(or_(
                Rol.nombre == 'Encargado de Recinto',
                Rol.nombre == 'Encargado de Unidad'
            ))
        )

        if busqueda:
            query = query.filter(
                or_(
                    Usuario.nombre_completo.ilike(f'%{busqueda}%'),
                    Usuario.rut.ilike(f'%{busqueda}%')
                )
            )

        encargados = query.order_by(Usuario.nombre_completo).paginate(
            page=page, per_page=10, error_out=False
        )

        return render_template('panel_jefa_salud.html',
                            pagination=encargados,
                            busqueda=busqueda)
    
    # Renombramos la ruta y la función
    @app.route('/ver_equipo_encargado/<int:encargado_id>')
    @login_required
    @check_password_change
    # El decorador @jefa_required ya no es correcto aquí, 
    # quitamos el decorador y dejamos que la lógica interna decida.
    def ver_equipo_encargado(encargado_id):
        page = request.args.get('page', 1, type=int)

        encargado = Usuario.query.get_or_404(encargado_id)
        
        # Verificación de permisos:
        # Solo permite ver el equipo si eres el jefe directo de ese encargado O eres Admin
        es_jefe_directo_del_encargado = (encargado.jefe_directo_id == current_user.id)
        es_admin = (current_user.rol.nombre == 'Admin')

        if not (es_jefe_directo_del_encargado or es_admin):
            abort(403)
            
        # Buscamos a los funcionarios cuyo jefe directo es el 'encargado_id'
        query = Usuario.query.filter_by(jefe_directo_id=encargado_id)

        funcionarios_equipo = query.order_by(Usuario.nombre_completo).paginate(
            page=page, per_page=10, error_out=False
        )

        return render_template('ver_equipo.html',
                            # Renombramos la variable 'jefe' por 'encargado'
                            encargado=encargado, 
                            pagination=funcionarios_equipo)
    
    @app.route('/anotacion/ver/<int:folio>', methods=['GET', 'POST'])
    @login_required
    def ver_anotacion(folio):
        anotacion = Anotacion.query.get_or_404(folio)

        # --- Medida de seguridad simplificada ---
        funcionario_de_anotacion = anotacion.funcionario

        es_el_funcionario = (current_user.id == funcionario_de_anotacion.id)
        es_admin = (current_user.rol.nombre == 'Admin')
        # Usamos nuestra función de ayuda
        es_superior = es_superior_jerarquico(current_user, funcionario_de_anotacion)

        # Permitir acceso si es el funcionario, un admin, o CUALQUIER superior en la cadena de mando
        if not (es_el_funcionario or es_admin or es_superior):
            abort(403)
        # --- Fin Medida de seguridad ---

        if request.method == 'POST':
            # Verificamos que el checkbox 'tomo_conocimiento' haya sido marcado
            if 'tomo_conocimiento' in request.form:
                # Actualizamos el estado de la anotación
                anotacion.estado = 'Aceptada'
                anotacion.fecha_aceptacion = datetime.now() # Guardamos fecha y hora
                
                # Guardamos las observaciones del funcionario (si las hay)
                observaciones = request.form.get('observacion_funcionario')
                anotacion.observacion_funcionario = observaciones if observaciones else "Sin observaciones."

                # --- ¡REGISTRAR LOG! ---
                detalles_log = (f"Funcionario {current_user.nombre_completo} (ID: {current_user.id}) "
                            f"aceptó la anotación Folio: {anotacion.folio}.")
                registrar_log(accion="Aceptación de Anotación", detalles=detalles_log)
                # ------------------------
                # Guardamos los cambios en la base de datos (anotación y log)
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
                # Generar token, guardar y enviar correo
                token = secrets.token_hex(16)
                expiracion = datetime.utcnow() + timedelta(hours=1)

                # Guardar token y expiración en el objeto usuario
                usuario.reset_token = token
                usuario.reset_token_expiracion = expiracion
                db.session.commit()

                # Enviar correo
                enviar_correo_reseteo(usuario, token)
                # Mensaje de éxito al usuario
                flash(f'Se ha enviado un enlace para restablecer la contraseña a {email}.', 'success')

            else:
                # Mensaje de error si el email no está registrado
                flash(f'El correo electrónico {email} no se encuentra registrado en el sistema.', 'danger')
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
    
    @app.route('/generar_pdf/<int:funcionario_id>')
    @login_required
    def generar_pdf(funcionario_id):
        # Medida de seguridad: Solo el propio funcionario, su jefe, o un admin pueden generar el PDF.
        funcionario = Usuario.query.get_or_404(funcionario_id)
        es_el_funcionario = (current_user.id == funcionario.id)
        es_el_jefe_directo = (current_user.id == funcionario.jefe_directo_id)
        es_admin = (current_user.rol.nombre == 'Admin')

        if not (es_el_funcionario or es_el_jefe_directo or es_admin):
            abort(403)

        # --- INICIO: Lógica de Filtros para el PDF ---
        tipo_filtro = request.args.get('tipo', '')
        factor_filtro = request.args.get('factor', '')
        fecha_inicio_str = request.args.get('fecha_inicio', '')
        fecha_fin_str = request.args.get('fecha_fin', '')

        # Empezamos con la consulta base de todas las anotaciones del funcionario
        query = Anotacion.query.filter_by(funcionario_id=funcionario.id)

        # Aplicamos los filtros si se proporcionaron
        if tipo_filtro:
            query = query.filter(Anotacion.tipo == tipo_filtro)
        
        if factor_filtro:
            query = query.join(Anotacion.subfactor).filter(SubFactor.factor_id == factor_filtro)
        # ¡NUEVO! Aplicar filtros de fecha si se proporcionaron
        try:
            if fecha_inicio_str:
                fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
                query = query.filter(Anotacion.fecha_creacion >= fecha_inicio)
            if fecha_fin_str:
                fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
                query = query.filter(Anotacion.fecha_creacion <= fecha_fin)
        except ValueError:
            flash("Formato de fecha inválido. Por favor, usa YYYY-MM-DD.", "danger")
            # Podríamos redirigir o manejar el error de otra forma
            return redirect(request.referrer or url_for('mi_hoja_de_vida')) # Vuelve a la página anterior
        
        # Obtenemos las anotaciones filtradas y ordenadas
        anotaciones = query.order_by(Anotacion.fecha_creacion.asc()).all()
        # --- FIN: Lógica de Filtros ---
        # (Opcional) Pasar las fechas al template del PDF para mostrarlas
        periodo_reporte = ""
        if fecha_inicio_str and fecha_fin_str:
            periodo_reporte = f"Período: {fecha_inicio.strftime('%d/%m/%Y')} - {fecha_fin.strftime('%d/%m/%Y')}"
        elif fecha_inicio_str:
            periodo_reporte = f"Desde: {fecha_inicio.strftime('%d/%m/%Y')}"
        elif fecha_fin_str:
            periodo_reporte = f"Hasta: {fecha_fin.strftime('%d/%m/%Y')}"
        fecha_actual = date.today().strftime('%d/%m/%Y')

        # Renderizamos la plantilla HTML con los datos (ya filtrados)
        html_renderizado = render_template('reporte_hoja_de_vida.html', 
                                        funcionario=funcionario, 
                                        anotaciones=anotaciones,
                                        fecha_actual=fecha_actual,
                                        periodo_reporte=periodo_reporte)

        # Usamos WeasyPrint para convertir el HTML a PDF
        pdf = HTML(string=html_renderizado).write_pdf()

        # Devolvemos el PDF al navegador
        return Response(pdf,
                        mimetype='application/pdf',
                        headers={'Content-Disposition': f'attachment;filename=hoja_de_vida_{funcionario.rut}.pdf'})
    
    @app.route('/api/unidades/<int:establecimiento_id>')
    @login_required
    def get_unidades_por_establecimiento(establecimiento_id):
        unidades = Unidad.query.filter_by(establecimiento_id=establecimiento_id).order_by(Unidad.nombre).all()
        # Convertimos la lista de objetos a un formato JSON que JS pueda leer
        unidades_lista = [{'id': u.id, 'nombre': u.nombre} for u in unidades]
        return jsonify(unidades_lista)
    
    # --- MANEJADOR DE ERROR CSRF ---
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """
        Captura los errores de token CSRF (ej. tokens vencidos en pestañas viejas)
        y redirige al usuario al login con un mensaje amigable.
        """
        # 1. Preparamos el mensaje amigable
        flash('Por favor, ingresa nuevamente.', 'warning')
        
        # 2. Redirigimos a la página de login
        return redirect(url_for('login'))
    # --- FIN MANEJADOR ---
    
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

def enviar_correo_notificacion_anotacion(anotacion):
    """Envía un correo al funcionario notificándole de una nueva anotación."""
    remitente = os.getenv("EMAIL_USUARIO")
    contrasena = os.getenv("EMAIL_CONTRASENA")
    
    if not remitente or not contrasena:
        print("ERROR: Credenciales de correo no configuradas en .env")
        return

    # Obtenemos los datos del destinatario y del emisor desde el objeto anotacion
    funcionario = anotacion.funcionario
    jefe = anotacion.jefe

    msg = MIMEMultipart()
    msg['Subject'] = f"Nueva Anotación en tu Hoja de Vida - Folio #{anotacion.folio}"
    msg['From'] = f"Sistema Hoja de Vida <{remitente}>"
    msg['To'] = funcionario.email
    
    # URL a la página de login
    url_sistema = url_for('login', _external=True)

    cuerpo_html = f"""
    <p>Hola {funcionario.nombre_completo},</p>
    <p>Has recibido una nueva anotación de tipo <strong>{anotacion.tipo}</strong> en tu Hoja de Vida, creada por <strong>{jefe.nombre_completo}</strong>.</p>
    <p>Para revisar los detalles, por favor ingresa al sistema:</p>
    <p><a href="{url_sistema}" style="padding: 10px 15px; background-color: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">Ingresar al Sistema</a></p>
    <p>Este es un correo generado automáticamente, por favor no respondas a esta dirección.</p>
    """
    msg.attach(MIMEText(cuerpo_html, 'html'))
    
    try:
        # Usamos 'with' para asegurar que la conexión se cierre correctamente
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(remitente, contrasena)
            server.send_message(msg)
            print(f"Correo de notificación enviado exitosamente a {funcionario.email}")
    except Exception as e:
        print(f"Error al enviar correo de notificación: {e}")

def registrar_log(accion, detalles=""):
    """
    Crea y añade un nuevo registro de log a la sesión de la base de datos.
    Nota: No hace commit aquí; el commit se debe hacer en la ruta principal.
    """
    # Intentamos obtener el usuario actual. Si no hay nadie logueado (ej: script), ponemos None.
    user_id = current_user.id if current_user.is_authenticated else None
    user_name = current_user.nombre_completo if current_user.is_authenticated else "Sistema"

    nuevo_log = Log(
        usuario_id=user_id,
        usuario_nombre=user_name,
        accion=accion,
        detalles=detalles
    )
    db.session.add(nuevo_log)
    # El db.session.commit() se hará en la ruta que llama a esta función.
    
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