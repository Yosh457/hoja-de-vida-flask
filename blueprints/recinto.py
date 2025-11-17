# blueprints/recinto.py
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from sqlalchemy import or_
from models import db, Usuario
from utils import encargado_recinto_required, check_password_change

recinto_bp = Blueprint('recinto', __name__, template_folder='../templates', url_prefix='/recinto')

@recinto_bp.route('/panel')
@login_required
@check_password_change
@encargado_recinto_required
def panel_encargado_recinto():
    page = request.args.get('page', 1, type=int)
    busqueda = request.args.get('busqueda', '')

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
    
    return render_template('panel_encargado_recinto.html',
                           pagination=encargados_unidad,
                           busqueda=busqueda)