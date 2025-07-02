from flask import Flask, render_template, g, request, jsonify, session, redirect, url_for
import sqlite3
import os
from werkzeug.utils import secure_filename
import traceback
import time
import base64
import secrets
from pycfdi_credentials import Certificate
from ocsp_proxy import validar_ocsp_proxy
from datetime import timedelta
from flask import make_response


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['DATABASE'] = os.path.join(BASE_DIR, 'instance', 'avaluo.db')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {
    'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx', 'xlsx', 'xls', 'txt',
    'kmz', 'kml', 'json', 'geojson'
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'rfc' not in session:
            return redirect(url_for('mostrar_login'))
        return f(*args, **kwargs)
    return decorated_function

# Unificada la ruta "/" para GET y POST
@app.route("/", methods=['GET', 'POST'])
def mostrar_login():
    if request.method == 'POST':
        print("🔵 POST recibido en /")
        data = request.get_json(silent=True)
        print("📦 JSON recibido:", data)
        print("🧠 Sesión actual:", dict(session))

        if data and data.get("salir"):
            session.clear()
            print("👋 Sesión cerrada")
        elif 'rfc' not in session and 'challenge' in session and all(
            k in data for k in ['certificado', 'firma_cadena', 'timestamp']
        ) and abs(time.time() - int(data['timestamp'])) <= 300:
            try:
                cert = Certificate(base64.b64decode(data['certificado']))
                if cert.verify(
                    base64.b64decode(data['firma_cadena']),
                    (f"{data['timestamp']}_{session['challenge']}").encode("utf-8"),
                    "sha256"
                ):
                    session['rfc'] = cert.subject.rfc
                    print("✅ Login exitoso para:", cert.subject.rfc)
            except Exception as e:
                print("❌ Error de verificación:", e)
                return jsonify({"error": "Validación fallida", "detalle": str(e)}), 400

        if 'rfc' not in session:
            session['challenge'] = secrets.token_hex(4)
            print("🧪 Nuevo challenge generado:", session['challenge'])

        return jsonify(dict(session))

    else:  # GET
        expired = session.pop('expired', False)
        return render_template("index.html", session_expired=expired)

# Cerrar sesión por inactividad
INACTIVITY_TIMEOUT_SECONDS = 200000

@app.before_request
def session_expiration_check():
    if 'rfc' in session:
        now = time.time()
        last_active = session.get('last_active', now)
        if now - last_active > INACTIVITY_TIMEOUT_SECONDS:
            session.clear()
            session['expired'] = True
            return redirect(url_for('mostrar_login'))
        else:
            session['last_active'] = now

# DEBUG TEMPORAL
@app.route('/debug_post', methods=['POST'])
def debug_post():
    try:
        data = request.get_json(silent=True)
        print("🧪 Datos recibidos:", data)
        return jsonify({"received": data or {}, "status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# HOME
@app.route('/home_buzon')
@login_required
def home():
    return render_template('home.html')

@app.route('/buzon')
@login_required
def buzon():
    db = get_db()
    cursor = db.execute("""
        SELECT a.id, a.clave, a.fecha_firmada 
        FROM avaluo_maestro a
        LEFT JOIN emision_avaluo_v2 e ON a.clave = e.clave_solicitud
        WHERE e.cadena_original IS NULL OR e.cadena_original = ''
        ORDER BY a.fecha_firmada
    """)
    tareas = cursor.fetchall()
    return render_template('buzon.html', tareas=tareas)

@app.route('/emisionAvaluo/<clave_solicitud>')
@login_required
def emisionAvaluo(clave_solicitud):
    db = get_db()
    cursor = db.execute('SELECT * FROM avaluo_maestro WHERE clave = ?', (clave_solicitud,))
    avaluo_maestro = cursor.fetchone()
    if avaluo_maestro is None:
        return "Tarea no encontrada", 404
    return render_template('emisionAvaluo.html', emisionAvaluo=avaluo_maestro)

@app.route('/emisionAvaluo/guardar', methods=['POST'])
def guardar_emision():
    try:
        clave_solicitud = request.form.get('clave_solicitud')
        servidor = request.form.get('servidor')
        valor_terreno = request.form.get('valor_terreno')
        perito_avaluo = request.form.get('perito_avaluo')
        superficie_metros = request.form.get('superficie_metros')
        clave_avaluo_maestro = request.form.get('clave_avaluo_maestro')
        uso_terreno = request.form.get('uso_terreno')
        archivo_avaluo = request.files.get('archivo_avaluo')

        if not archivo_avaluo or archivo_avaluo.filename == '':
            return jsonify({"status": "error", "message": "No se subió ningún archivo"}), 400

        if not allowed_file(archivo_avaluo.filename):
            return jsonify({"status": "error", "message": "Tipo de archivo no permitido"}), 400

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM emision_avaluo_v2 WHERE clave_solicitud = ?", (clave_solicitud,))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": f"Ya existe un registro con la clave_solicitud '{clave_solicitud}'"}), 409

        filename = secure_filename(archivo_avaluo.filename)
        archivo_avaluo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        cursor.execute("""
            INSERT INTO emision_avaluo_v2
            (clave_solicitud, servidor, valor_terreno, perito_avaluo, superficie_metros, clave_avaluo_maestro, uso_terreno, archivo_avaluo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (clave_solicitud, servidor, valor_terreno, perito_avaluo, superficie_metros, clave_avaluo_maestro, uso_terreno, filename))
        db.commit()

        return jsonify({"status": "ok", "message": "Datos guardados correctamente"})

    except Exception as e:
        db.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/emisionAvaluo/firmado', methods=['POST'])
def firmado_emision_save():
    try:
        print("📥 POST recibido en /emisionAvaluo/firmado")

        clave_solicitud = request.form.get('clave_solicitud')
        rfc_firmante = request.form.get('rfc_firmante')
        firma_digital = request.form.get('firma_digital')
        fecha_firmada = request.form.get('fecha_firmada')
        cadena_original = request.form.get('cadena_original')

        # Debug de todos los campos
        print("🧾 Datos recibidos:")
        print(f"🔑 clave_solicitud: {clave_solicitud}")
        print(f"👤 rfc_firmante: {rfc_firmante}")
        print(f"🖋️ firma_digital: {firma_digital}")
        print(f"📅 fecha_firmada: {fecha_firmada}")
        print(f"📜 cadena_original: {cadena_original}")

        # Validación
        if not all([clave_solicitud, rfc_firmante, firma_digital, fecha_firmada, cadena_original]):
            print("❌ Validación fallida: Faltan uno o más campos obligatorios")
            return jsonify({"status": "error", "message": "Faltan datos para guardar la firma"}), 400

        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE emision_avaluo_v2
            SET rfc_firmante = ?, firma_digital = ?, fecha_firmada = ?, cadena_original = ?
            WHERE clave_solicitud = ?
        """, (rfc_firmante, firma_digital, fecha_firmada, cadena_original, clave_solicitud))

        if cursor.rowcount == 0:
            print("⚠️ No se encontró el registro para actualizar")
            return jsonify({"status": "error", "message": "Registro no encontrado para actualizar firma"}), 404

        db.commit()
        print("✅ Firma guardada correctamente")
        return jsonify({"status": "ok", "message": "Firma guardada correctamente"})

    except Exception as e:
        db.rollback()
        print(f"🔥 Error inesperado al guardar firma: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/emisionAvaluo/firmado/<clave_solicitud>')
@login_required
def firmado_emision(clave_solicitud):
    db = get_db()
    cursor = db.execute('SELECT * FROM emision_avaluo_v2 WHERE clave_solicitud = ?', (clave_solicitud,))
    registro = cursor.fetchone()
    if registro is None:
        return "Registro no encontrado", 404
    
    response = make_response(render_template('resumenFirma.html', clave_solicitud=clave_solicitud))

    # Evitar cache para que no se pueda regresar a la página anterior con 'atrás'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return render_template('firmadoEmisionAvaluo.html', emision=registro)

@app.route('/resumen_firma/<clave_solicitud>')
@login_required
def resumen_firma(clave_solicitud):
    db = get_db()
    registro = db.execute('SELECT * FROM emision_avaluo_v2 WHERE clave_solicitud = ?', (clave_solicitud,)).fetchone()
    if not registro:
        return "Registro no encontrado", 404
    return render_template('resumenFirma.html', clave_solicitud=clave_solicitud)

@app.route('/seguimientos')
@login_required
def seguimientos():
    db = get_db()
    cursor = db.execute('SELECT * FROM emision_avaluo_v2 ORDER BY ID')
    registros = cursor.fetchall()
    return render_template('seguimientos.html', registros=registros)

def crear_tabla_emision_avaluo():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emision_avaluo_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        clave_solicitud TEXT UNIQUE,
        servidor TEXT NOT NULL,
        valor_terreno REAL NOT NULL,
        perito_avaluo TEXT NOT NULL,
        superficie_metros REAL NOT NULL,
        clave_avaluo_maestro TEXT NOT NULL,
        uso_terreno TEXT NOT NULL,
        archivo_avaluo TEXT NOT NULL,
        rfc_firmante TEXT,
        firma_digital TEXT,
        fecha_firmada TEXT,
        cadena_original TEXT,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    db.commit()

if __name__ == '__main__':
    with app.app_context():
        crear_tabla_emision_avaluo()
    app.run(host='0.0.0.0', port=5050, debug=True)
