import os
import shutil
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, 
    url_for, flash, session, g, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash

# Cliente HTTP liviano para Turso (Evita errores de hilos/Rust en Render)
try:
    import libsql_client
except ImportError:
    libsql_client = None

app = Flask(__name__)

# -------------------------------------------------------------------
# CONFIGURACIÓN DE SEGURIDAD Y SESIONES (AJUSTADO)
# -------------------------------------------------------------------
app.secret_key = os.environ.get('SECRET_KEY', 'clave_secreta_iglesia_app_clave_segura')

# Expiración automática tras 4 horas de inactividad
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)

# Banderas de seguridad para cookies (Protección anti Session Hijacking y XSS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

# Credenciales de Turso (Variables de Entorno)
TURSO_URL = os.environ.get('TURSO_DATABASE_URL')
TURSO_TOKEN = os.environ.get('TURSO_AUTH_TOKEN')
DATABASE = 'database.db'
BACKUP_DIR = 'backups'

_db_initialized = False

# -------------------------------------------------------------------
# INYECCIÓN DE USUARIO GLOBAL EN PLANTILLAS (SEGURIDAD DE VISTA)
# -------------------------------------------------------------------
@app.context_processor
def inject_user():
    """Hace disponible 'current_user' en todas las plantillas HTML."""
    if 'user_id' in session:
        return dict(current_user={
            'id': session.get('user_id'),
            'nombre': session.get('nombre'),
            'username': session.get('username')
        })
    return dict(current_user=None)

# -------------------------------------------------------------------
# MANEJO DE BASE DE DATOS
# -------------------------------------------------------------------
def get_db():
    if 'db' not in g:
        if TURSO_URL and TURSO_TOKEN and libsql_client is not None:
            g.db = libsql_client.create_client_sync(url=TURSO_URL, auth_token=TURSO_TOKEN)
        else:
            g.db = sqlite3.connect(DATABASE)
            g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        if hasattr(db, 'close'):
            db.close()

def execute_query(db, query, params=()):
    if hasattr(db, 'execute'):
        return db.execute(query, params)
    return None

def init_db():
    db = get_db()
    
    execute_query(db, '''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nombre TEXT NOT NULL,
            rol TEXT DEFAULT 'admin'
        )
    ''')

    execute_query(db, '''
        CREATE TABLE IF NOT EXISTS miembros (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            cedula TEXT,
            telefono TEXT,
            direccion TEXT,
            fecha_nacimiento TEXT,
            bautizado INTEGER DEFAULT 0,
            sociedad TEXT DEFAULT 'General',
            estado TEXT DEFAULT 'Activo'
        )
    ''')

    execute_query(db, '''
        CREATE TABLE IF NOT EXISTS servicios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            tipo_servicio TEXT NOT NULL,
            director TEXT,
            predicador TEXT,
            observaciones TEXT
        )
    ''')

    execute_query(db, '''
        CREATE TABLE IF NOT EXISTS asistencia (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            servicio_id INTEGER NOT NULL,
            miembro_id INTEGER NOT NULL,
            asistio INTEGER DEFAULT 0,
            FOREIGN KEY (servicio_id) REFERENCES servicios (id) ON DELETE CASCADE,
            FOREIGN KEY (miembro_id) REFERENCES miembros (id) ON DELETE CASCADE
        )
    ''')

    execute_query(db, '''
        CREATE TABLE IF NOT EXISTS tesoreria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo TEXT NOT NULL,
            monto REAL NOT NULL,
            categoria TEXT,
            sociedad TEXT DEFAULT 'General',
            descripcion TEXT,
            fecha TEXT NOT NULL
        )
    ''')

    execute_query(db, '''
        CREATE TABLE IF NOT EXISTS anuncios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            contenido TEXT NOT NULL,
            fecha TEXT NOT NULL
        )
    ''')

    try:
        execute_query(db, "SELECT sociedad FROM tesoreria LIMIT 1")
    except Exception:
        try:
            execute_query(db, "ALTER TABLE tesoreria ADD COLUMN sociedad TEXT DEFAULT 'General'")
        except Exception:
            pass

    try:
        res = execute_query(db, 'SELECT COUNT(*) FROM usuarios WHERE username = ?', ('admin',))
        admin_count = 0
        if res:
            if hasattr(res, 'rows'):
                admin_count = res.rows[0][0] if res.rows else 0
            else:
                row = res.fetchone()
                admin_count = row[0] if row else 0

        if admin_count == 0:
            execute_query(
                db,
                'INSERT INTO usuarios (username, password, nombre, rol) VALUES (?, ?, ?, ?)',
                ('admin', generate_password_hash('admin123'), 'Administrador', 'admin')
            )
    except Exception:
        pass

    if hasattr(db, 'commit'):
        db.commit()

@app.before_request
def initialize_on_first_request():
    global _db_initialized
    if not _db_initialized:
        try:
            init_db()
            _db_initialized = True
        except Exception as e:
            print(f"Error inicializando DB: {e}")

# -------------------------------------------------------------------
# DECORADOR DE SEGURIDAD (PROTECCIÓN DE RUTAS ADMIN)
# -------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Acceso denegado. Debes iniciar sesión para ingresar al área administrativa.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------------------------------------------
# PORTAL PÚBLICO (Cualquiera puede entrar)
# -------------------------------------------------------------------
@app.route('/')
@app.route('/portal', endpoint='portal')
@app.route('/index', endpoint='index')
def portal():
    db = get_db()
    res_s = execute_query(db, 'SELECT * FROM servicios ORDER BY fecha DESC LIMIT 5')
    servicios = res_s.rows if hasattr(res_s, 'rows') else res_s.fetchall()

    res_a = execute_query(db, 'SELECT * FROM anuncios ORDER BY id DESC LIMIT 5')
    anuncios = res_a.rows if hasattr(res_a, 'rows') else res_a.fetchall()

    return render_template('portal.html', servicios=servicios, anuncios=anuncios)

# -------------------------------------------------------------------
# AUTENTICACIÓN
# -------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        res = execute_query(db, 'SELECT * FROM usuarios WHERE username = ?', (username,))
        
        user = None
        if hasattr(res, 'rows'):
            if res.rows:
                cols = res.columns
                user = dict(zip(cols, res.rows[0]))
        else:
            user = res.fetchone()

        if user and check_password_hash(user['password'], password):
            session.clear() # Limpia cualquier rastro previo de sesión
            session.permanent = True # Activa la expiración por inactividad
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nombre'] = user['nombre']
            flash(f'Sesión iniciada correctamente. ¡Bienvenido, {user["nombre"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear() # Destruye completamente la cookie y sesión en el servidor
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('portal'))

# -------------------------------------------------------------------
# PANEL ADMINISTRATIVO (PROTEGIDO CON @login_required)
# -------------------------------------------------------------------
@app.route('/dashboard', endpoint='dashboard')
@login_required
def dashboard():
    db = get_db()
    
    res_m = execute_query(db, 'SELECT COUNT(*) FROM miembros WHERE estado = "Activo"')
    total_miembros = (res_m.rows[0][0] if hasattr(res_m, 'rows') and res_m.rows else res_m.fetchone()[0]) or 0

    res_s = execute_query(db, 'SELECT COUNT(*) FROM servicios')
    total_servicios = (res_s.rows[0][0] if hasattr(res_s, 'rows') and res_s.rows else res_s.fetchone()[0]) or 0

    res_i = execute_query(db, 'SELECT SUM(monto) FROM tesoreria WHERE tipo = "ingreso"')
    val_i = (res_i.rows[0][0] if hasattr(res_i, 'rows') and res_i.rows else res_i.fetchone()[0])
    total_ingresos = float(val_i) if val_i else 0.0

    res_e = execute_query(db, 'SELECT SUM(monto) FROM tesoreria WHERE tipo = "egreso"')
    val_e = (res_e.rows[0][0] if hasattr(res_e, 'rows') and res_e.rows else res_e.fetchone()[0])
    total_egresos = float(val_e) if val_e else 0.0

    balance = total_ingresos - total_egresos

    res_mov = execute_query(db, 'SELECT * FROM tesoreria ORDER BY id DESC LIMIT 5')
    ultimos_movimientos = res_mov.rows if hasattr(res_mov, 'rows') else res_mov.fetchall()

    res_anu = execute_query(db, 'SELECT * FROM anuncios ORDER BY id DESC LIMIT 5')
    anuncios = res_anu.rows if hasattr(res_anu, 'rows') else res_anu.fetchall()

    return render_template('index.html',
                           total_miembros=total_miembros,
                           total_servicios=total_servicios,
                           total_ingresos=total_ingresos,
                           total_egresos=total_egresos,
                           balance=balance,
                           ultimos_movimientos=ultimos_movimientos,
                           anuncios=anuncios)

# -------------------------------------------------------------------
# RESTO DE MÓDULOS ADMINISTRATIVOS (TODOS PROTEGIDOS)
# -------------------------------------------------------------------
@app.route('/crear_anuncio', methods=['POST'])
@login_required
def crear_anuncio():
    titulo = request.form.get('titulo')
    contenido = request.form.get('contenido')
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M')

    if titulo and contenido:
        db = get_db()
        execute_query(db, 'INSERT INTO anuncios (titulo, contenido, fecha) VALUES (?, ?, ?)', (titulo, contenido, fecha))
        if hasattr(db, 'commit'): db.commit()
        flash('Anuncio publicado.', 'success')
    else:
        flash('Campos incompletos.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/anuncios/eliminar/<int:id>')
@login_required
def eliminar_anuncio(id):
    db = get_db()
    execute_query(db, 'DELETE FROM anuncios WHERE id = ?', (id,))
    if hasattr(db, 'commit'): db.commit()
    flash('Anuncio eliminado.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/miembros', methods=['GET', 'POST'])
@login_required
def miembros():
    db = get_db()
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        telefono = request.form.get('telefono')
        direccion = request.form.get('direccion')
        fecha_nacimiento = request.form.get('fecha_nacimiento')
        bautizado = 1 if request.form.get('bautizado') == '1' else 0
        sociedad = request.form.get('sociedad', 'General')

        if not nombre:
            flash('Nombre obligatorio.', 'danger')
            return redirect(url_for('miembros'))

        try:
            execute_query(
                db,
                'INSERT INTO miembros (nombre, cedula, telefono, direccion, fecha_nacimiento, bautizado, sociedad) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (nombre, None, telefono, direccion, fecha_nacimiento, bautizado, sociedad)
            )
            if hasattr(db, 'commit'): db.commit()
            flash('Miembro registrado.', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

        return redirect(url_for('miembros'))

    res = execute_query(db, 'SELECT * FROM miembros ORDER BY nombre ASC')
    lista_miembros = res.rows if hasattr(res, 'rows') else res.fetchall()
    return render_template('miembros.html', miembros=lista_miembros)

@app.route('/miembros/editar/<int:id>', methods=['POST'])
@login_required
def editar_miembro(id):
    db = get_db()
    nombre = request.form.get('nombre')
    telefono = request.form.get('telefono')
    direccion = request.form.get('direccion')
    fecha_nacimiento = request.form.get('fecha_nacimiento')
    bautizado = 1 if request.form.get('bautizado') == '1' else 0
    sociedad = request.form.get('sociedad', 'General')
    estado = request.form.get('estado', 'Activo')

    try:
        execute_query(db, '''
            UPDATE miembros 
            SET nombre = ?, telefono = ?, direccion = ?, fecha_nacimiento = ?, bautizado = ?, sociedad = ?, estado = ?
            WHERE id = ?
        ''', (nombre, telefono, direccion, fecha_nacimiento, bautizado, sociedad, estado, id))
        if hasattr(db, 'commit'): db.commit()
        flash('Miembro actualizado.', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('miembros'))

@app.route('/miembros/eliminar/<int:id>')
@login_required
def eliminar_miembro(id):
    db = get_db()
    execute_query(db, 'DELETE FROM miembros WHERE id = ?', (id,))
    execute_query(db, 'DELETE FROM asistencia WHERE miembro_id = ?', (id,))
    if hasattr(db, 'commit'): db.commit()
    flash('Miembro eliminado.', 'info')
    return redirect(url_for('miembros'))

@app.route('/servicios', methods=['GET', 'POST'], endpoint='servicios')
@app.route('/secretaria', endpoint='secretaria')
@login_required
def servicios():
    db = get_db()
    if request.method == 'POST':
        fecha = request.form.get('fecha')
        tipo_servicio = request.form.get('tipo_servicio')
        director = request.form.get('director')
        predicador = request.form.get('predicador')
        observaciones = request.form.get('observaciones')

        execute_query(
            db,
            'INSERT INTO servicios (fecha, tipo_servicio, director, predicador, observaciones) VALUES (?, ?, ?, ?, ?)',
            (fecha, tipo_servicio, director, predicador, observaciones)
        )
        if hasattr(db, 'commit'): db.commit()

        res_id = execute_query(db, 'SELECT MAX(id) FROM servicios')
        servicio_id = (res_id.rows[0][0] if hasattr(res_id, 'rows') and res_id.rows else res_id.fetchone()[0])

        flash('Servicio registrado.', 'success')
        return redirect(url_for('asistencia', servicio_id=servicio_id))

    res = execute_query(db, 'SELECT * FROM servicios ORDER BY id DESC')
    lista_servicios = res.rows if hasattr(res, 'rows') else res.fetchall()
    return render_template('servicios.html', servicios=lista_servicios)

@app.route('/servicios/eliminar/<int:id>')
@login_required
def eliminar_servicio(id):
    db = get_db()
    execute_query(db, 'DELETE FROM servicios WHERE id = ?', (id,))
    execute_query(db, 'DELETE FROM asistencia WHERE servicio_id = ?', (id,))
    if hasattr(db, 'commit'): db.commit()
    flash('Servicio eliminado.', 'info')
    return redirect(url_for('servicios'))

@app.route('/asistencia/<int:servicio_id>', methods=['GET', 'POST'], endpoint='asistencia')
@app.route('/asistencia/<int:servicio_id>', methods=['GET', 'POST'], endpoint='tomar_asistencia')
@login_required
def asistencia(servicio_id):
    db = get_db()
    res_s = execute_query(db, 'SELECT * FROM servicios WHERE id = ?', (servicio_id,))
    servicio = (res_s.rows[0] if hasattr(res_s, 'rows') and res_s.rows else res_s.fetchone())

    if not servicio:
        flash('Servicio no encontrado.', 'danger')
        return redirect(url_for('servicios'))

    if request.method == 'POST':
        execute_query(db, 'DELETE FROM asistencia WHERE servicio_id = ?', (servicio_id,))

        asistentes = request.form.getlist('asistio')
        res_m = execute_query(db, 'SELECT id FROM miembros WHERE estado = "Activo"')
        todos_miembros = res_m.rows if hasattr(res_m, 'rows') else res_m.fetchall()

        for m in todos_miembros:
            m_id = m[0]
            asistio = 1 if str(m_id) in asistentes else 0
            execute_query(
                db,
                'INSERT INTO asistencia (servicio_id, miembro_id, asistio) VALUES (?, ?, ?)',
                (servicio_id, m_id, asistio)
            )
        if hasattr(db, 'commit'): db.commit()
        flash('Asistencia guardada.', 'success')
        return redirect(url_for('servicios'))

    res_m_list = execute_query(db, '''
        SELECT m.id, m.nombre, m.sociedad, COALESCE(a.asistio, 0) as asistio
        FROM miembros m
        LEFT JOIN asistencia a ON m.id = a.miembro_id AND a.servicio_id = ?
        WHERE m.estado = "Activo"
        ORDER BY m.nombre ASC
    ''', (servicio_id,))
    miembros = res_m_list.rows if hasattr(res_m_list, 'rows') else res_m_list.fetchall()

    return render_template('asistencia.html', servicio=servicio, miembros=miembros)

@app.route('/tesoreria', methods=['GET', 'POST'])
@login_required
def tesoreria():
    sociedad_filtro = request.args.get('sociedad', 'Todas')
    db = get_db()

    if request.method == 'POST':
        tipo = request.form.get('tipo')
        categoria = request.form.get('categoria')
        sociedad = request.form.get('sociedad', 'General')
        descripcion = request.form.get('descripcion')
        fecha = datetime.now().strftime('%Y-%m-%d %H:%M')

        try:
            monto = float(request.form.get('monto', 0))
            if monto <= 0:
                raise ValueError
        except (ValueError, TypeError):
            flash('Monto inválido.', 'danger')
            return redirect(url_for('tesoreria', sociedad=sociedad))

        execute_query(
            db,
            'INSERT INTO tesoreria (tipo, monto, categoria, sociedad, descripcion, fecha) VALUES (?, ?, ?, ?, ?, ?)',
            (tipo, monto, categoria, sociedad, descripcion, fecha)
        )
        if hasattr(db, 'commit'): db.commit()
        flash('Movimiento financiero registrado.', 'success')
        return redirect(url_for('tesoreria', sociedad=sociedad))

    if sociedad_filtro != 'Todas':
        res_mov = execute_query(db, 'SELECT * FROM tesoreria WHERE sociedad = ? ORDER BY id DESC', (sociedad_filtro,))
        res_i = execute_query(db, 'SELECT SUM(monto) FROM tesoreria WHERE tipo = "ingreso" AND sociedad = ?', (sociedad_filtro,))
        res_e = execute_query(db, 'SELECT SUM(monto) FROM tesoreria WHERE tipo = "egreso" AND sociedad = ?', (sociedad_filtro,))
    else:
        res_mov = execute_query(db, 'SELECT * FROM tesoreria ORDER BY id DESC')
        res_i = execute_query(db, 'SELECT SUM(monto) FROM tesoreria WHERE tipo = "ingreso"')
        res_e = execute_query(db, 'SELECT SUM(monto) FROM tesoreria WHERE tipo = "egreso"')

    movimientos = res_mov.rows if hasattr(res_mov, 'rows') else res_mov.fetchall()
    val_i = (res_i.rows[0][0] if hasattr(res_i, 'rows') and res_i.rows else res_i.fetchone()[0])
    total_ingresos = float(val_i) if val_i else 0.0

    val_e = (res_e.rows[0][0] if hasattr(res_e, 'rows') and res_e.rows else res_e.fetchone()[0])
    total_egresos = float(val_e) if val_e else 0.0

    balance = total_ingresos - total_egresos

    return render_template('tesoreria.html',
                           movimientos=movimientos,
                           total_ingresos=total_ingresos,
                           total_egresos=total_egresos,
                           balance=balance,
                           sociedad_filtro=sociedad_filtro)

@app.route('/tesoreria/eliminar/<int:id>')
@login_required
def eliminar_tesoreria(id):
    db = get_db()
    execute_query(db, 'DELETE FROM tesoreria WHERE id = ?', (id,))
    if hasattr(db, 'commit'): db.commit()
    flash('Movimiento eliminado.', 'info')
    return redirect(request.referrer or url_for('tesoreria'))

@app.route('/seguridad')
@login_required
def seguridad():
    return render_template('seguridad.html')

@app.route('/seguridad/descargar-db')
@login_required
def descargar_db():
    if os.path.exists(DATABASE):
        fecha_actual = datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(
            DATABASE,
            as_attachment=True,
            download_name=f'respaldo_base_datos_{fecha_actual}.db'
        )
    flash('Archivo no encontrado.', 'danger')
    return redirect(url_for('seguridad'))

@app.route('/seguridad/respaldar-db', methods=['POST'])
@login_required
def respaldar_db():
    if os.path.exists(DATABASE):
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
        fecha_actual = datetime.now().strftime('%Y%m%d_%H%M%S')
        destino = os.path.join(BACKUP_DIR, f'backup_local_{fecha_actual}.db')
        shutil.copy2(DATABASE, destino)
        flash('Respaldo local generado.', 'success')
    else:
        flash('Base de datos local no encontrada.', 'danger')
    return redirect(url_for('seguridad'))

@app.route('/seguridad/eliminar-db', methods=['POST'])
@login_required
def eliminar_db():
    admin_password = request.form.get('admin_password')
    user_id = session.get('user_id')
    
    db = get_db()
    res = execute_query(db, 'SELECT * FROM usuarios WHERE id = ?', (user_id,))
    user = (res.rows[0] if hasattr(res, 'rows') and res.rows else res.fetchone())

    pass_hash = user[2] if hasattr(res, 'rows') else user['password']
    
    if user and check_password_hash(pass_hash, admin_password):
        if os.path.exists(DATABASE):
            if not os.path.exists(BACKUP_DIR):
                os.makedirs(BACKUP_DIR)
            fecha_actual = datetime.now().strftime('%Y%m%d_%H%M%S')
            shutil.copy2(DATABASE, os.path.join(BACKUP_DIR, f'backup_pre_eliminar_{fecha_actual}.db'))

        execute_query(db, 'DELETE FROM miembros')
        execute_query(db, 'DELETE FROM servicios')
        execute_query(db, 'DELETE FROM asistencia')
        execute_query(db, 'DELETE FROM tesoreria')
        execute_query(db, 'DELETE FROM anuncios')
        if hasattr(db, 'commit'): db.commit()
        
        flash('Registros borrados correctamente.', 'warning')
    else:
        flash('Contraseña incorrecta.', 'danger')
        
    return redirect(url_for('seguridad'))

if __name__ == '__main__':
    app.run(debug=True)
