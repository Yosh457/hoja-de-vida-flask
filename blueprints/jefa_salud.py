# blueprints/jefa_salud.py
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from sqlalchemy import or_
from models import db, Usuario, Rol
from utils import jefa_required, check_password_change

jefa_salud_bp = Blueprint('jefa_salud', __name__, template_folder='../templates', url_prefix='/jefa')

@jefa_salud_bp.route('/panel')
@login_required
@check_password_change
@jefa_required
def panel_jefa_salud():
    page = request.args.get('page', 1, type=int)
    busqueda = request.args.get('busqueda', '')

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