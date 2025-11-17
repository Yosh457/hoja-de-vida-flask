# blueprints/admin.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import or_

# Importamos modelos y utilidades
from models import db, Usuario, Rol, Unidad, Establecimiento, CalidadJuridica, Categoria, Log
from utils import admin_required, check_password_change, registrar_log

# Creamos el Blueprint
# url_prefix='/admin' significa que todas las rutas aquí empezarán automáticamente con /admin
admin_bp = Blueprint('admin', __name__, template_folder='../templates', url_prefix='/admin')

@admin_bp.route('/panel')
@login_required
@check_password_change
@admin_required
def admin_panel():
    page = request.args.get('page', 1, type=int)
    
    # --- Lógica de Filtros ---
    busqueda = request.args.get('busqueda', '')
    rol_filtro = request.args.get('rol_filtro', '')
    unidad_filtro = request.args.get('unidad_filtro', '')
    estado_filtro = request.args.get('estado_filtro', '')

    query = Usuario.query

    if busqueda:
        query = query.filter(
            or_(
                Usuario.nombre_completo.ilike(f'%{busqueda}%'),
                Usuario.email.ilike(f'%{busqueda}%')
            )
        )
    
    if rol_filtro:
        query = query.filter(Usuario.rol_id == rol_filtro)
    if unidad_filtro:
        query = query.filter(Usuario.unidad_id == unidad_filtro)
    if estado_filtro:
        if estado_filtro == 'activo':
            query = query.filter(Usuario.activo == True)
        elif estado_filtro == 'inactivo':
            query = query.filter(Usuario.activo == False)
    
    roles_para_filtro = Rol.query.order_by(Rol.nombre).all()
    unidades_para_filtro = Unidad.query.order_by(Unidad.nombre).all()

    pagination = query.order_by(Usuario.id).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('admin_panel.html', 
                        pagination=pagination,
                        roles_para_filtro=roles_para_filtro,
                        unidades_para_filtro=unidades_para_filtro,
                        busqueda=busqueda,
                        rol_filtro=rol_filtro,
                        unidad_filtro=unidad_filtro,
                        estado_filtro=estado_filtro)

@admin_bp.route('/crear_usuario', methods=['GET', 'POST'])
@login_required
@admin_required
def crear_usuario():
    if request.method == 'POST':
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

        if Usuario.query.filter_by(email=email).first():
            flash('El correo electrónico ya está registrado.', 'danger')
            # Nota: usamos .crear_usuario porque estamos dentro del mismo blueprint
            return redirect(url_for('admin.crear_usuario'))
        if Usuario.query.filter_by(rut=rut).first():
            flash('El RUT ya está registrado.', 'danger')
            return redirect(url_for('admin.crear_usuario'))

        nuevo_usuario = Usuario(
            rut=rut,
            nombre_completo=nombre,
            email=email,
            rol_id=rol_id,
            unidad_id=unidad_id,
            establecimiento_id=establecimiento_id,
            calidad_juridica_id=calidad_id,
            categoria_id=categoria_id,
            jefe_directo_id=jefe_id if jefe_id else None,
        )
        nuevo_usuario.set_password(password)
        nuevo_usuario.cambio_clave_requerido = forzar_cambio
        db.session.add(nuevo_usuario)
        db.session.commit()

        flash('Usuario creado con éxito.', 'success')
        return redirect(url_for('admin.admin_panel'))

    roles = Rol.query.order_by(Rol.nombre).all()
    unidades = Unidad.query.order_by(Unidad.nombre).all()
    establecimientos = Establecimiento.query.order_by(Establecimiento.nombre).all()
    calidades = CalidadJuridica.query.order_by(CalidadJuridica.nombre).all()
    categorias = Categoria.query.order_by(Categoria.nombre).all()
    
    # Filtro complejo para jefes
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

@admin_bp.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(id):
    usuario_a_editar = Usuario.query.get_or_404(id)

    if request.method == 'POST':
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

        password = request.form.get('password')
        if password:
            usuario_a_editar.set_password(password)
        
        db.session.commit()
        flash('Usuario actualizado con éxito.', 'success')
        return redirect(url_for('admin.admin_panel'))

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

@admin_bp.route('/toggle_activo/<int:id>', methods=['POST'])
@login_required
@admin_required
def toggle_activo(id):
    usuario = Usuario.query.get_or_404(id)
    usuario.activo = not usuario.activo
    
    accion_realizada = "Activación" if usuario.activo else "Desactivación"
    detalles_log = (f"Admin {current_user.nombre_completo} (ID: {current_user.id}) realizó "
                f"{accion_realizada} del usuario {usuario.nombre_completo} (ID: {usuario.id}).")
    registrar_log(accion=f"{accion_realizada} de Usuario", detalles=detalles_log)
    db.session.commit()
    
    if usuario.activo:
        flash(f'El usuario {usuario.nombre_completo} ha sido activado.', 'success')
    else:
        flash(f'El usuario {usuario.nombre_completo} ha sido desactivado.', 'warning')
        
    return redirect(url_for('admin.admin_panel'))

@admin_bp.route('/ver_logs')
@login_required
@check_password_change
@admin_required
def ver_logs():
    page = request.args.get('page', 1, type=int)
    usuario_filtro_id = request.args.get('usuario_id', '')
    accion_filtro = request.args.get('accion', '')

    query = Log.query.order_by(Log.timestamp.desc())

    if usuario_filtro_id:
        query = query.filter(Log.usuario_id == usuario_filtro_id)
    if accion_filtro:
        query = query.filter(Log.accion == accion_filtro)
        
    logs_pagination = query.paginate(page=page, per_page=15, error_out=False)
    todos_los_usuarios = Usuario.query.order_by(Usuario.nombre_completo).all()
    
    acciones_posibles = [
        "Inicio de Sesión",
        "Cierre de Sesión",
        "Creación de Comentario",
        "Aceptación de Comentario",
        "Activación de Usuario",
        "Desactivación de Usuario"
    ]
    
    filtros_actuales = {
        'usuario_id': usuario_filtro_id,
        'accion': accion_filtro
    }

    return render_template('ver_logs.html',
                        pagination=logs_pagination,
                        todos_los_usuarios=todos_los_usuarios,
                        acciones_posibles=acciones_posibles,
                        filtros=filtros_actuales)