import os
import shutil
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, 
    url_for, flash, session, g, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash

# Importación condicional para evitar fallos en Pydroid 3 / Android
try:
    import libsql_experimental as libsql
except ImportError:
    try:
        import libsql
    except ImportError:
        libsql = None

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'clave_secreta_iglesia_app_clave_segura')

# Credenciales de Turso (Variables de Entorno)
TURSO_URL = os.environ.get('TURSO_DATABASE_URL')
TURSO_TOKEN = os.environ.get('TURSO_AUTH_TOKEN')
DATABASE = 'database.db'
BACKUP_DIR = 'backups'

# -------------------------------------------------------------------
# MANEJO DE BASE DE DATOS (HÍBRIDO: TURSO NUBE / SQLITE LOCAL)
# -------------------------------------------------------------------
def get_db():
    if 'db' not in g:
        # Solo conecta a Turso si hay credenciales Y el módulo está instalado (Render)
        if TURSO_URL and TURSO_TOKEN and libsql is not None:
            g.db = libsql.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)
        else:
            # Respaldo local a SQLite para Pydroid 3 o desarrollo local
            g.db = sqlite3.connect(DATABASE)
            g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Inicializa la base de datos y crea las tablas si no existen."""
    with app.app_context():
        db = get_db()
        
        # Tabla de Usuarios
        db.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                nombre TEXT NOT NULL,
                rol TEXT DEFAULT 'admin'
            )
        ''')

        # Tabla de Miembros
        db.execute('''
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

        # Tabla de Servicios y Cultos
        db.execute('''
            CREATE TABLE IF NOT EXISTS servicios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TEXT NOT NULL,
                tipo_servicio TEXT NOT NULL,
                director TEXT,
                predicador TEXT,
                observaciones TEXT
            )
        ''')

        # Tabla de Asistencia
        db.execute('''
            CREATE TABLE IF NOT EXISTS asistencia (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                servicio_id INTEGER NOT NULL,
                miembro_id INTEGER NOT NULL,
                asistio INTEGER DEFAULT 0,
                FOREIGN KEY (servicio_id) REFERENCES servicios (id) ON DELETE CASCADE,
                FOREIGN KEY (miembro_id) REFERENCES miembros (id) ON DELETE CASCADE
            )
        ''')

        # Tabla de Tesorería
        db.execute('''
            CREATE TABLE IF NOT EXISTS tesoreria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT NOT NULL,          -- 'ingreso' o 'egreso'
                monto REAL NOT NULL,
                categoria TEXT,              -- 'Diezmo', 'Ofrenda', 'Mantenimiento', etc.
                sociedad TEXT DEFAULT 'General', -- 'General', 'Jóvenes', 'Damas', 'Caballeros', etc.
                descripcion TEXT,
                fecha TEXT NOT NULL
            )
        ''')

        # Tabla de Anuncios / Cartelera
        db.execute('''
            CREATE TABLE IF NOT EXISTS anuncios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                contenido TEXT NOT NULL,
                fecha TEXT NOT NULL
            )
        ''')

        # Migración ligera: Verificar si la columna 'sociedad' existe en 'tesoreria'
        try:
            db.execute("SELECT sociedad FROM tesoreria LIMIT 1")
        except Exception:
            try:
                db.execute("ALTER TABLE tesoreria ADD COLUMN sociedad TEXT DEFAULT 'General'")
            except Exception:
                pass

        # Crear usuario administrador por defecto si no existe ninguno
        cursor = db.execute('SELECT COUNT(*) FROM usuarios WHERE username = ?', ('admin',))
        row = cursor.fetchone()
        admin_count = row[0] if row else 0

        if admin_count == 0:
            db.execute(
                'INSERT INTO usuarios (username, password, nombre, rol) VALUES (?, ?, ?, ?)',
                ('admin', generate_password_hash('admin123'), 'Administrador', 'admin')
            )

        db.commit()

# Inicializar DB al arrancar la aplicación
init_db()

# -------------------------------------------------------------------
# DECORADORES Y SEGURIDAD
# -------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, inicia sesión para continuar.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------------------------------------------
# PORTAL / VISTA INICIAL PÚBLICA (Pasa servicios y anuncios)
# -------------------------------------------------------------------
@app.route('/')
@app.route('/portal', endpoint='portal')
@app.route('/index', endpoint='index')
def portal():
    """Página de inicio pública del sistema."""
    db = get_db()
    servicios = db.execute('SELECT * FROM servicios ORDER BY fecha DESC LIMIT 5').fetchall()
    anuncios = db.execute('SELECT * FROM anuncios ORDER BY id DESC LIMIT 5').fetchall()
    
    return render_template('portal.html', servicios=servicios, anuncios=anuncios)

# -------------------------------------------------------------------
# RUTAS DE AUTENTICACIÓN
# -------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        user = db.execute('SELECT * FROM usuarios WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nombre'] = user['nombre']
            flash(f'¡Bienvenido de nuevo, {user["nombre"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))

# -------------------------------------------------------------------
# DASHBOARD / PANEL PRINCIPAL
# -------------------------------------------------------------------
@app.route('/dashboard', endpoint='dashboard')
@login_required
def dashboard():
    db = get_db()
    
    res_m = db.execute('SELECT COUNT(*) FROM miembros WHERE estado = "Activo"').fetchone()
    total_miembros = res_m[0] if res_m else 0

    res_s = db.execute('SELECT COUNT(*) FROM servicios').fetchone()
    total_servicios = res_s[0] if res_s else 0

    res_i = db.execute('SELECT SUM(monto) FROM tesoreria WHERE tipo = "ingreso"').fetchone()
    total_ingresos = (res_i[0] or 0.0) if res_i else 0.0

    res_e = db.execute('SELECT SUM(monto) FROM tesoreria WHERE tipo = "egreso"').fetchone()
    total_egresos = (res_e[0] or 0.0) if res_e else 0.0

    balance = total_ingresos - total_egresos

    ultimos_movimientos = db.execute('SELECT * FROM tesoreria ORDER BY id DESC LIMIT 5').fetchall()
    anuncios = db.execute('SELECT * FROM anuncios ORDER BY id DESC LIMIT 5').fetchall()

    return render_template('index.html',
                           total_miembros=total_miembros,
                           total_servicios=total_servicios,
                           total_ingresos=total_ingresos,
                           total_egresos=total_egresos,
                           balance=balance,
                           ultimos_movimientos=ultimos_movimientos,
                           anuncios=anuncios)

# -------------------------------------------------------------------
# MÓDULO DE ANUNCIOS
# -------------------------------------------------------------------
@app.route('/crear_anuncio', methods=['POST'])
@login_required
def crear_anuncio():
    titulo = request.form.get('titulo')
    contenido = request.form.get('contenido')
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M')

    if titulo and contenido:
        db = get_db()
        db.execute('INSERT INTO anuncios (titulo, contenido, fecha) VALUES (?, ?, ?)', (titulo, contenido, fecha))
        db.commit()
        flash('Anuncio publicado con éxito.', 'success')
    else:
        flash('El título y contenido del anuncio son obligatorios.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/anuncios/eliminar/<int:id>')
@login_required
def eliminar_anuncio(id):
    db = get_db()
    db.execute('DELETE FROM anuncios WHERE id = ?', (id,))
    db.commit()
    flash('Anuncio eliminado correctamente.', 'info')
    return redirect(url_for('dashboard'))

# -------------------------------------------------------------------
# MÓDULO DE MIEMBROS (SIN SOLICITAR CÉDULA)
# -------------------------------------------------------------------
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
            flash('El nombre del miembro es obligatorio.', 'danger')
            return redirect(url_for('miembros'))

        try:
            # Enviamos None a la columna cedula para evitar bloqueos por restricción UNIQUE
            db.execute(
                'INSERT INTO miembros (nombre, cedula, telefono, direccion, fecha_nacimiento, bautizado, sociedad) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (nombre, None, telefono, direccion, fecha_nacimiento, bautizado, sociedad)
            )
            db.commit()
            flash('Miembro registrado exitosamente.', 'success')
        except Exception as e:
            flash(f'Error al guardar el miembro: {str(e)}', 'danger')

        return redirect(url_for('miembros'))

    lista_miembros = db.execute('SELECT * FROM miembros ORDER BY nombre ASC').fetchall()
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
        db.execute('''
            UPDATE miembros 
            SET nombre = ?, telefono = ?, direccion = ?, fecha_nacimiento = ?, bautizado = ?, sociedad = ?, estado = ?
            WHERE id = ?
        ''', (nombre, telefono, direccion, fecha_nacimiento, bautizado, sociedad, estado, id))
        db.commit()
        flash('Datos del miembro actualizados correctamente.', 'success')
    except Exception as e:
        flash(f'Error al actualizar el miembro: {str(e)}', 'danger')

    return redirect(url_for('miembros'))

@app.route('/miembros/eliminar/<int:id>')
@login_required
def eliminar_miembro(id):
    db = get_db()
    db.execute('DELETE FROM miembros WHERE id = ?', (id,))
    db.execute('DELETE FROM asistencia WHERE miembro_id = ?', (id,))
    db.commit()
    flash('Miembro eliminado del sistema.', 'info')
    return redirect(url_for('miembros'))

# -------------------------------------------------------------------
# MÓDULO DE SERVICIOS Y CULTOS (Soporta 'servicios' y 'secretaria')
# -------------------------------------------------------------------
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

        cursor = db.execute(
            'INSERT INTO servicios (fecha, tipo_servicio, director, predicador, observaciones) VALUES (?, ?, ?, ?, ?)',
            (fecha, tipo_servicio, director, predicador, observaciones)
        )
        db.commit()

        servicio_id = cursor.lastrowid
        flash('Servicio registrado con éxito. Puedes tomar la asistencia.', 'success')
        return redirect(url_for('asistencia', servicio_id=servicio_id))

    lista_servicios = db.execute('SELECT * FROM servicios ORDER BY id DESC').fetchall()
    return render_template('servicios.html', servicios=lista_servicios)

@app.route('/servicios/eliminar/<int:id>')
@login_required
def eliminar_servicio(id):
    db = get_db()
    db.execute('DELETE FROM servicios WHERE id = ?', (id,))
    db.execute('DELETE FROM asistencia WHERE servicio_id = ?', (id,))
    db.commit()
    flash('Servicio y su registro de asistencia eliminados.', 'info')
    return redirect(url_for('servicios'))

# -------------------------------------------------------------------
# MÓDULO DE ASISTENCIA (Soporta 'asistencia' y 'tomar_asistencia')
# -------------------------------------------------------------------
@app.route('/asistencia/<int:servicio_id>', methods=['GET', 'POST'], endpoint='asistencia')
@app.route('/asistencia/<int:servicio_id>', methods=['GET', 'POST'], endpoint='tomar_asistencia')
@login_required
def asistencia(servicio_id):
    db = get_db()
    servicio = db.execute('SELECT * FROM servicios WHERE id = ?', (servicio_id,)).fetchone()

    if not servicio:
        flash('El servicio no existe.', 'danger')
        return redirect(url_for('servicios'))

    if request.method == 'POST':
        db.execute('DELETE FROM asistencia WHERE servicio_id = ?', (servicio_id,))

        asistentes = request.form.getlist('asistio')
        todos_miembros = db.execute('SELECT id FROM miembros WHERE estado = "Activo"').fetchall()

        for m in todos_miembros:
            m_id = m['id'] if isinstance(m, dict) or hasattr(m, '__getitem__') else m[0]
            asistio = 1 if str(m_id) in asistentes else 0
            db.execute(
                'INSERT INTO asistencia (servicio_id, miembro_id, asistio) VALUES (?, ?, ?)',
                (servicio_id, m_id, asistio)
            )
        db.commit()
        flash('Asistencia guardada correctamente.', 'success')
        return redirect(url_for('servicios'))

    miembros = db.execute('''
        SELECT m.id, m.nombre, m.sociedad, COALESCE(a.asistio, 0) as asistio
        FROM miembros m
        LEFT JOIN asistencia a ON m.id = a.miembro_id AND a.servicio_id = ?
        WHERE m.estado = "Activo"
        ORDER BY m.nombre ASC
    ''', (servicio_id,)).fetchall()

    return render_template('asistencia.html', servicio=servicio, miembros=miembros)

# -------------------------------------------------------------------
# MÓDULO DE TESORERÍA Y FINANZAS
# -------------------------------------------------------------------
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
            flash('Por favor ingresa un monto válido mayor a 0.', 'danger')
            return redirect(url_for('tesoreria', sociedad=sociedad))

        db.execute(
            'INSERT INTO tesoreria (tipo, monto, categoria, sociedad, descripcion, fecha) VALUES (?, ?, ?, ?, ?, ?)',
            (tipo, monto, categoria, sociedad, descripcion, fecha)
        )
        db.commit()
        flash('Movimiento financiero registrado correctamente.', 'success')
        return redirect(url_for('tesoreria', sociedad=sociedad))

    if sociedad_filtro != 'Todas':
        movimientos = db.execute('SELECT * FROM tesoreria WHERE sociedad = ? ORDER BY id DESC', (sociedad_filtro,)).fetchall()
        res_i = db.execute('SELECT SUM(monto) FROM tesoreria WHERE tipo = "ingreso" AND sociedad = ?', (sociedad_filtro,)).fetchone()
        total_ingresos = (res_i[0] or 0.0) if res_i else 0.0
        
        res_e = db.execute('SELECT SUM(monto) FROM tesoreria WHERE tipo = "egreso" AND sociedad = ?', (sociedad_filtro,)).fetchone()
        total_egresos = (res_e[0] or 0.0) if res_e else 0.0
    else:
        movimientos = db.execute('SELECT * FROM tesoreria ORDER BY id DESC').fetchall()
        res_i = db.execute('SELECT SUM(monto) FROM tesoreria WHERE tipo = "ingreso"').fetchone()
        total_ingresos = (res_i[0] or 0.0) if res_i else 0.0
        
        res_e = db.execute('SELECT SUM(monto) FROM tesoreria WHERE tipo = "egreso"').fetchone()
        total_egresos = (res_e[0] or 0.0) if res_e else 0.0

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
    db.execute('DELETE FROM tesoreria WHERE id = ?', (id,))
    db.commit()
    flash('Movimiento financiero eliminado correctamente.', 'info')
    return redirect(request.referrer or url_for('tesoreria'))

# -------------------------------------------------------------------
# MÓDULO DE SEGURIDAD Y RESPALDOS
# -------------------------------------------------------------------
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
    flash('No se encontró el archivo de base de datos local para desc
