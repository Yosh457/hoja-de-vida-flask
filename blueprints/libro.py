# blueprints/libro.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify, abort
from flask_login import login_required, current_user
from datetime import date, datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# Importamos modelos y utilidades
from models import db, Usuario, Comentario, Factor, SubFactor, Unidad
from utils import check_password_change, registrar_log, enviar_correo_notificacion_comentario, es_superior_jerarquico

libro_bp = Blueprint('libro', __name__, template_folder='../templates')

@libro_bp.route('/libro_novedades')
@login_required
@check_password_change
def mi_libro_novedades():
    page = request.args.get('page', 1, type=int)
    tipo_filtro = request.args.get('tipo_filtro', '')
    factor_filtro = request.args.get('factor_filtro', '')
    subfactor_filtro = request.args.get('subfactor_filtro', '')
    fecha_inicio_str = request.args.get('fecha_inicio', '')
    fecha_fin_str = request.args.get('fecha_fin', '')

    query = Comentario.query.filter_by(funcionario_id=current_user.id)
    if tipo_filtro:
        query = query.filter(Comentario.tipo == tipo_filtro)
    if factor_filtro:
        query = query.join(Comentario.subfactor).filter(SubFactor.factor_id == factor_filtro)
    if subfactor_filtro:
        query = query.filter(Comentario.subfactor_id == subfactor_filtro)
    
    comentarios_pendientes = query.filter(Comentario.estado == 'Pendiente').order_by(Comentario.folio.desc()).all()
    historial_query = query.filter(Comentario.estado == 'Aceptada')
    
    try:
        if fecha_inicio_str:
            fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
            historial_query = historial_query.filter(Comentario.fecha_creacion >= fecha_inicio)
        if fecha_fin_str:
            fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
            historial_query = historial_query.filter(Comentario.fecha_creacion <= fecha_fin)
    except ValueError:
        flash("Formato de fecha inválido. Por favor, usa YYYY-MM-DD.", "danger")
        return redirect(request.path) 

    historial_pagination = historial_query.order_by(Comentario.fecha_creacion.desc(), Comentario.folio.desc()).paginate(
        page=page, per_page=5, error_out=False
    )
    
    factores_para_filtro = [{'id': f.id, 'nombre': f.nombre} for f in Factor.query.order_by(Factor.nombre).all()]
    subfactores_para_filtro = [{'id': sf.id, 'nombre': sf.nombre, 'factor_id': sf.factor_id} for sf in SubFactor.query.all()]

    return render_template('mi_libro_novedades.html', 
                        comentarios_pendientes=comentarios_pendientes,
                        historial_pagination=historial_pagination,
                        factores_para_filtro=factores_para_filtro,
                        subfactores_para_filtro=subfactores_para_filtro,
                        tipo_filtro=tipo_filtro,
                        factor_filtro=factor_filtro,
                        subfactor_filtro=subfactor_filtro,
                        fecha_inicio=fecha_inicio_str,
                        fecha_fin=fecha_fin_str)

@libro_bp.route('/libro_novedades/<int:funcionario_id>')
@login_required
@check_password_change
def ver_libro_novedades_funcionario(funcionario_id):
    page = request.args.get('page', 1, type=int)
    funcionario = Usuario.query.get_or_404(funcionario_id)
    
    es_admin = (current_user.rol.nombre == 'Admin')
    es_superior = es_superior_jerarquico(current_user, funcionario)

    if not (es_admin or es_superior):
        abort(403)

    tipo_filtro = request.args.get('tipo_filtro', '')
    factor_filtro = request.args.get('factor_filtro', '')
    subfactor_filtro = request.args.get('subfactor_filtro', '')
    fecha_inicio_str = request.args.get('fecha_inicio', '')
    fecha_fin_str = request.args.get('fecha_fin', '')
    
    query = Comentario.query.filter_by(funcionario_id=funcionario.id)
    if tipo_filtro:
        query = query.filter(Comentario.tipo == tipo_filtro)
    if factor_filtro:
        query = query.join(Comentario.subfactor).filter(SubFactor.factor_id == factor_filtro)
    if subfactor_filtro:
        query = query.filter(Comentario.subfactor_id == subfactor_filtro)

    comentarios_pendientes = query.filter(Comentario.estado == 'Pendiente').order_by(Comentario.folio.desc()).all()
    historial_query = query.filter(Comentario.estado == 'Aceptada')

    try:
        if fecha_inicio_str:
            fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
            historial_query = historial_query.filter(Comentario.fecha_creacion >= fecha_inicio)
        if fecha_fin_str:
            fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
            historial_query = historial_query.filter(Comentario.fecha_creacion <= fecha_fin)
    except ValueError:
        flash("Formato de fecha inválido. Por favor, usa YYYY-MM-DD.", "danger")
        return redirect(request.path) 

    historial_pagination = historial_query.order_by(Comentario.fecha_creacion.desc(), Comentario.folio.desc()).paginate(
        page=page, per_page=5, error_out=False
    )
    
    factores_para_filtro = [{'id': f.id, 'nombre': f.nombre} for f in Factor.query.order_by(Factor.nombre).all()]
    subfactores_para_filtro = [{'id': sf.id, 'nombre': sf.nombre, 'factor_id': sf.factor_id} for sf in SubFactor.query.all()]
    
    return render_template('libro_novedades_funcionario.html', 
                        funcionario=funcionario, 
                        comentarios_pendientes=comentarios_pendientes,
                        historial_pagination=historial_pagination,
                        factores_para_filtro=factores_para_filtro,
                        subfactores_para_filtro=subfactores_para_filtro,
                        tipo_filtro=tipo_filtro,
                        factor_filtro=factor_filtro,
                        subfactor_filtro=subfactor_filtro,
                        fecha_inicio=fecha_inicio_str,
                        fecha_fin=fecha_fin_str)

@libro_bp.route('/crear_comentario/<int:funcionario_id>', methods=['GET', 'POST'])
@login_required
@check_password_change 
def crear_comentario(funcionario_id):
    funcionario = Usuario.query.get_or_404(funcionario_id)

    puede_anotar = False
    if (current_user.rol.nombre == 'Jefa Salud' and
        funcionario.rol.nombre in ['Encargado de Recinto', 'Encargado de Unidad'] and
        funcionario.jefe_directo_id == current_user.id):
        puede_anotar = True
    elif (current_user.rol.nombre == 'Encargado de Recinto' and
          funcionario.rol.nombre == 'Encargado de Unidad' and
          funcionario.jefe_directo_id == current_user.id):
        puede_anotar = True
    elif (current_user.rol.nombre == 'Encargado de Unidad' and
          funcionario.rol.nombre == 'Funcionario' and
          funcionario.jefe_directo_id == current_user.id):
        puede_anotar = True
    elif current_user.rol.nombre == 'Admin':
        puede_anotar = True

    if not puede_anotar:
        flash('No tienes permisos para crear comentarios a este usuario.', 'danger')
        # Usamos las nuevas rutas de blueprints
        if current_user.rol.nombre == 'Jefa Salud':
            return redirect(url_for('jefa_salud.panel_jefa_salud'))
        elif current_user.rol.nombre == 'Encargado de Recinto':
            return redirect(url_for('recinto.panel_encargado_recinto'))
        elif current_user.rol.nombre == 'Encargado de Unidad':
            return redirect(url_for('unidad.panel_encargado_unidad'))
        else:
            return redirect(url_for('libro.mi_libro_novedades'))

    if request.method == 'POST':
        tipo = request.form.get('tipo')
        subfactor_id = request.form.get('subfactor_id')
        motivo = request.form.get('motivo_jefe')

        nuevo_comentario = Comentario(
            tipo=tipo,
            motivo_jefe=motivo,
            fecha_creacion=date.today(),
            funcionario_id=funcionario.id,
            jefe_id=current_user.id,
            subfactor_id=subfactor_id
        )
        db.session.add(nuevo_comentario)
        db.session.flush()

        detalles_log = (f"Jefe {current_user.nombre_completo} (ID: {current_user.id}) creó comentario "
                    f"{nuevo_comentario.tipo} (Folio: {nuevo_comentario.folio}) para "
                    f"{funcionario.nombre_completo} (ID: {funcionario.id}). "
                    f"Factor: {nuevo_comentario.subfactor.factor.nombre}, "
                    f"SubFactor: {nuevo_comentario.subfactor.nombre}.")
        registrar_log(accion="Creación de Comentario", detalles=detalles_log)
        db.session.commit()
        enviar_correo_notificacion_comentario(nuevo_comentario)
        flash(f'Comentario creado con éxito para {funcionario.nombre_completo}.', 'success')

        # Redirecciones usando blueprints
        if current_user.rol.nombre == 'Jefa Salud':
            return redirect(url_for('jefa_salud.panel_jefa_salud'))
        elif current_user.rol.nombre == 'Encargado de Recinto':
            return redirect(url_for('recinto.panel_encargado_recinto'))
        elif current_user.rol.nombre == 'Encargado de Unidad':
            return redirect(url_for('unidad.panel_encargado_unidad'))
        else: 
            return redirect(url_for('admin.admin_panel'))
        
    factores = Factor.query.order_by(Factor.id).all()
    subfactores = SubFactor.query.order_by(SubFactor.id).all()

    return render_template('crear_comentario.html', 
                           funcionario=funcionario, 
                           factores=factores, 
                           subfactores=subfactores)

@libro_bp.route('/comentario/ver/<int:folio>', methods=['GET', 'POST'])
@login_required
def ver_comentario(folio):
    comentario = Comentario.query.get_or_404(folio)
    funcionario_del_comentario = comentario.funcionario
    es_el_funcionario = (current_user.id == funcionario_del_comentario.id)
    es_admin = (current_user.rol.nombre == 'Admin')
    es_superior = es_superior_jerarquico(current_user, funcionario_del_comentario)

    if not (es_el_funcionario or es_admin or es_superior):
        abort(403)

    if request.method == 'POST':
        if 'tomo_conocimiento' in request.form:
            comentario.estado = 'Aceptada'
            comentario.fecha_aceptacion = datetime.now()
            observaciones = request.form.get('observacion_funcionario')
            comentario.observacion_funcionario = observaciones if observaciones else "Sin observaciones."

            detalles_log = (f"Funcionario {current_user.nombre_completo} (ID: {current_user.id}) "
                        f"aceptó el comentario Folio: {comentario.folio}.")
            registrar_log(accion="Aceptación de Comentario", detalles=detalles_log)
            db.session.commit()

            flash('Has confirmado la lectura del comentario.', 'success')
            return redirect(url_for('libro.mi_libro_novedades'))
        else:
            flash('Debes marcar la casilla "Tomo conocimiento" para confirmar.', 'warning')
    
    return render_template('ver_comentario.html', comentario=comentario)

@libro_bp.route('/ver_equipo_encargado/<int:encargado_id>')
@login_required
@check_password_change
def ver_equipo_encargado(encargado_id):
    page = request.args.get('page', 1, type=int)
    encargado = Usuario.query.get_or_404(encargado_id)
    es_jefe_directo_del_encargado = (encargado.jefe_directo_id == current_user.id)
    es_admin = (current_user.rol.nombre == 'Admin')

    if not (es_jefe_directo_del_encargado or es_admin):
        abort(403)
        
    query = Usuario.query.filter_by(jefe_directo_id=encargado_id)
    funcionarios_equipo = query.order_by(Usuario.nombre_completo).paginate(page=page, per_page=10, error_out=False)

    return render_template('ver_equipo.html',
                        encargado=encargado, 
                        pagination=funcionarios_equipo)

# API para JS (usada en formularios)
@libro_bp.route('/api/unidades/<int:establecimiento_id>')
@login_required
def get_unidades_por_establecimiento(establecimiento_id):
    unidades = Unidad.query.filter_by(establecimiento_id=establecimiento_id).order_by(Unidad.nombre).all()
    unidades_lista = [{'id': u.id, 'nombre': u.nombre} for u in unidades]
    return jsonify(unidades_lista)

# --- GENERACIÓN DE PDF (USANDO FPDF2 PARA SERVIDOR LINUX) ---
@libro_bp.route('/generar_pdf/<int:funcionario_id>')
@login_required
def generar_pdf(funcionario_id):
    funcionario = Usuario.query.get_or_404(funcionario_id)
    es_el_funcionario = (current_user.id == funcionario.id)
    es_superior = es_superior_jerarquico(current_user, funcionario)
    es_admin = (current_user.rol.nombre == 'Admin')

    if not (es_el_funcionario or es_superior or es_admin):
        abort(403)

    tipo_filtro = request.args.get('tipo', '')
    factor_filtro = request.args.get('factor', '')
    fecha_inicio_str = request.args.get('fecha_inicio', '')
    fecha_fin_str = request.args.get('fecha_fin', '')

    query = Comentario.query.filter_by(funcionario_id=funcionario.id)

    if tipo_filtro:
        query = query.filter(Comentario.tipo == tipo_filtro)
    if factor_filtro:
        query = query.join(Comentario.subfactor).filter(SubFactor.factor_id == factor_filtro)
    try:
        if fecha_inicio_str:
            fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
            query = query.filter(Comentario.fecha_creacion >= fecha_inicio)
        if fecha_fin_str:
            fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
            query = query.filter(Comentario.fecha_creacion <= fecha_fin)
    except ValueError:
        flash("Formato de fecha inválido. Por favor, usa YYYY-MM-DD.", "danger")
        return redirect(request.referrer or url_for('libro.mi_libro_novedades'))
    
    comentarios = query.order_by(Comentario.fecha_creacion.asc()).all()
    
    # Preparar textos
    periodo_reporte = ""
    if fecha_inicio_str and fecha_fin_str:
        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d')
        periodo_reporte = f"Periodo: {fecha_inicio.strftime('%d/%m/%Y')} - {fecha_fin.strftime('%d/%m/%Y')}"
    elif fecha_inicio_str:
         fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
         periodo_reporte = f"Desde: {fecha_inicio.strftime('%d/%m/%Y')}"
    elif fecha_fin_str:
         fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d')
         periodo_reporte = f"Hasta: {fecha_fin.strftime('%d/%m/%Y')}"
    fecha_actual = date.today().strftime('%d/%m/%Y')

    # --- FPDF2 LOGIC ---
    pdf = FPDF(orientation='P', unit='mm', format='Letter')
    pdf.add_page()
    pdf.set_font('Helvetica', '', 11)
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, 'Reporte de Registros de Eventos Funcionarios', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C') 
    pdf.ln(10)

    pdf.set_font('Helvetica', '', 11)
    pdf.set_fill_color(248, 249, 250)
    pdf.set_draw_color(222, 226, 230)
    pdf.set_line_width(0.3)
    info = (
        f"Funcionario: {funcionario.nombre_completo}\n"
        f"RUT: {funcionario.rut}\n"
        f"Unidad: {funcionario.unidad.nombre}\n"
        f"Fecha de Generacion: {fecha_actual}\n"
    )
    if periodo_reporte:
         info += f"{periodo_reporte}"

    pdf.multi_cell(0, 6, info, border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT, padding=5)
    pdf.ln(10)

    if not comentarios:
        pdf.set_font('Helvetica', '', 11)
        pdf.cell(0, 10, 'El funcionario no tiene comentarios registrados para los filtros seleccionados.', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        ancho_etiqueta = 60
        ancho_valor = pdf.w - pdf.l_margin - pdf.r_margin - ancho_etiqueta
        altura_linea = 6

        for comentario in comentarios:
            table_data = [
                ("Tipo de Comentario", comentario.tipo, True),
                ("Factor / Sub-Factor", f"{comentario.subfactor.factor.nombre} / {comentario.subfactor.nombre}", False),
                ("Creada por (Jefatura)", comentario.jefe.nombre_completo, False),
                ("Estado", comentario.estado, False),
                ("Motivo (Jefatura)", comentario.motivo_jefe or 'Sin respuesta.', False),
                ("Observaciones (Funcionario)", comentario.observacion_funcionario or 'Sin respuesta.', False),
            ]
            if comentario.fecha_aceptacion:
                table_data.append(("Fecha Aceptacion", comentario.fecha_aceptacion.strftime('%d/%m/%Y a las %H:%M:%S'), False))

            altura_total_tabla = 8 
            pdf.set_font('Helvetica', 'B', 10)
            lineas_por_fila = []
            for etiqueta, valor, _ in table_data:
                lineas_etiqueta = len(pdf.multi_cell(w=ancho_etiqueta, h=altura_linea, txt=etiqueta, dry_run=True, split_only=True))
                pdf.set_font('Helvetica', '', 10)
                lineas_valor = len(pdf.multi_cell(w=ancho_valor, h=altura_linea, txt=str(valor), dry_run=True, split_only=True))
                lineas_max = max(lineas_etiqueta, lineas_valor)
                lineas_por_fila.append(lineas_max)
                altura_total_tabla += lineas_max * altura_linea

            if pdf.get_y() + altura_total_tabla > pdf.page_break_trigger:
                pdf.add_page()
            
            pdf.set_font('Helvetica', 'B', 11)
            pdf.set_fill_color(52, 73, 94)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 8, f"Folio #{comentario.folio} - Fecha: {comentario.fecha_creacion.strftime('%d/%m/%Y')}", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True, align='C')
            pdf.set_text_color(0, 0, 0)
            pdf.set_draw_color(204, 204, 204)
            pdf.set_line_width(0.2)

            for i, (etiqueta, valor, es_tipo) in enumerate(table_data):
                y_antes = pdf.get_y()
                num_lineas = lineas_por_fila[i]
                altura_celda = num_lineas * altura_linea

                pdf.set_font('Helvetica', 'B', 10)
                pdf.multi_cell(ancho_etiqueta, altura_linea, etiqueta, border='L', align='L', new_x=XPos.RIGHT, new_y=YPos.TOP, max_line_height=altura_linea) 
                
                pdf.set_xy(pdf.l_margin + ancho_etiqueta, y_antes)
                
                pdf.set_font('Helvetica', '', 10)
                if es_tipo:
                    if valor == 'Favorable':
                        pdf.set_text_color(25, 135, 84)
                    else:
                        pdf.set_text_color(220, 53, 69)
                
                pdf.multi_cell(ancho_valor, altura_linea, str(valor), border='R', align='L', new_x=XPos.LMARGIN, new_y=YPos.NEXT, max_line_height=altura_linea) 
                
                pdf.set_text_color(0, 0, 0)
                pdf.line(pdf.l_margin, y_antes + altura_celda, pdf.w - pdf.r_margin, y_antes + altura_celda)
                pdf.set_y(y_antes + altura_celda) 

            pdf.ln(10)

    return Response(bytes(pdf.output()),
                    mimetype='application/pdf',
                    headers={'Content-Disposition': f'attachment;filename=libro_novedades_{funcionario.rut}.pdf'})