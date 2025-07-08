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
import hashlib
import uuid

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
        SELECT 
            a.id AS id,
            a.clave AS clave,
            a.fecha_firmada AS fecha_firmada,
            CASE 
                WHEN e.id IS NOT NULL THEN 1 
                ELSE 0 
            END AS capturado,
            CASE 
                WHEN e.cadena_original IS NOT NULL AND e.cadena_original != '' THEN 1 
                ELSE 0 
            END AS firmado
        FROM avaluo_maestro a
        LEFT JOIN emision_avaluo e ON a.clave = e.clave_solicitud
        WHERE e.firma_digital IS NULL OR e.firma_digital = ''
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



def calcular_hash_archivo(archivo):
    if archivo is None:
        print("⚠️ Archivo es None")
        return None
    try:
        hasher = hashlib.sha256()
        archivo.stream.seek(0)
        total_bytes = 0
        while True:
            chunk = archivo.stream.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
            total_bytes += len(chunk)
        archivo.stream.seek(0)
        print(f"✔️ Leyó {total_bytes} bytes para calcular hash")
        return hasher.hexdigest()
    except Exception as e:
        print("❌ Error al calcular hash:", e)
        return None


@app.route('/emisionAvaluo/guardar', methods=['POST'])
def guardar_emision():
    try:
        # 🔽 Obtención de datos del formulario
        clave_solicitud = request.form.get('clave_solicitud')
        servidor = request.form.get('servidor')
        perito_avaluo = request.form.get('perito_avaluo')
        clave_avaluo_maestro = request.form.get('clave_avaluo_maestro')
        uso_terreno = request.form.get('uso_terreno')
        archivo_avaluo = request.files.get('archivo_avaluo')

        # 🔽 Conversión segura a float (evita errores con campos vacíos)
        valor_terreno = request.form.get('valor_terreno')
        superficie_metros = request.form.get('superficie_metros')
        try:
            valor_terreno = float(valor_terreno)
            superficie_metros = float(superficie_metros)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Los valores numéricos son inválidos"}), 400

        # 🔽 Validaciones básicas
        if not all([clave_solicitud, servidor, valor_terreno, perito_avaluo,
                    superficie_metros, clave_avaluo_maestro, uso_terreno]):
            return jsonify({"status": "error", "message": "Faltan campos obligatorios"}), 400

        if not archivo_avaluo or archivo_avaluo.filename == '':
            return jsonify({"status": "error", "message": "No se subió ningún archivo"}), 400

        if not allowed_file(archivo_avaluo.filename):
            return jsonify({"status": "error", "message": "Tipo de archivo no permitido"}), 400

        # 🔽 Calcular hash del archivo
        hash_archivo = calcular_hash_archivo(archivo_avaluo)
        print("🔑 Hash calculado:", hash_archivo)

        # 🔽 Guardar archivo con nombre seguro
        # filename = secure_filename(archivo_avaluo.filename)
        # archivo_avaluo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))


       

        # 🔽 Guardar archivo con nombre seguro y UUID
        filename = secure_filename(archivo_avaluo.filename)
        oid = str(uuid.uuid4())
        carpeta_oid = os.path.join(app.config['UPLOAD_FOLDER'], oid)
        os.makedirs(carpeta_oid, exist_ok=True)
        ruta_completa = os.path.join(carpeta_oid, filename)
        archivo_avaluo.save(ruta_completa)

        # Guardar en DB el path relativo o nombre (para luego encontrarlo)
        archivo_guardado = f"{oid}/{filename}"


        # 🔽 Log de todos los datos (debug)
        print("🔎 Datos a guardar:")
        print(f"clave_solicitud: {clave_solicitud}")
        print(f"servidor: {servidor}")
        print(f"valor_terreno: {valor_terreno}")
        print(f"perito_avaluo: {perito_avaluo}")
        print(f"superficie_metros: {superficie_metros}")
        print(f"clave_avaluo_maestro: {clave_avaluo_maestro}")
        print(f"uso_terreno: {uso_terreno}")
        print(f"archivo: {filename}")
        print(f"hash: {hash_archivo}")

        # 🔽 Insertar en base de datos
        db = get_db()
        cursor = db.cursor()
        # Guardar en DB el valor con carpeta + nombre
        archivo_guardado = f"{oid}/{filename}"

        # Verificar si ya existe
        cursor.execute("SELECT id FROM emision_avaluo WHERE clave_solicitud = ?", (clave_solicitud,))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": f"Ya existe un registro con la clave_solicitud '{clave_solicitud}'"}), 409

        cursor.execute("""
            INSERT INTO emision_avaluo
            (clave_solicitud, servidor, valor_terreno, perito_avaluo, superficie_metros, clave_avaluo_maestro, uso_terreno, archivo_avaluo, hash_archivo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (clave_solicitud, servidor, valor_terreno, perito_avaluo, superficie_metros, clave_avaluo_maestro, uso_terreno, archivo_guardado, hash_archivo))
        db.commit()

        return jsonify({"status": "ok", "message": "Datos guardados correctamente"})

    except Exception as e:
        db.rollback()
        print("🔥 Error inesperado:", traceback.format_exc())
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
        certificado_base64 = request.form.get('certificado')  # Nuevo
        nombre_firmante = request.form.get('nombre_firmante')


        # Debug de todos los campos
        print("🧾 Datos recibidos:")
        print(f"🔑 clave_solicitud: {clave_solicitud}")
        print(f"👤 rfc_firmante: {rfc_firmante}")
        print(f"🖋️ firma_digital: {firma_digital}")
        print(f"📅 fecha_firmada: {fecha_firmada}")
        print(f"📜 cadena_original: {cadena_original}")
        print(f"📄 certificado_base64: {'Sí' if certificado_base64 else 'No'}")
        print("📄 certificado_base64 length:", len(certificado_base64) if certificado_base64 else 0)


        # Validación
        if not all([clave_solicitud, rfc_firmante, firma_digital, fecha_firmada, cadena_original]):
            print("❌ Validación fallida: Faltan uno o más campos obligatorios")
            return jsonify({"status": "error", "message": "Faltan datos para guardar la firma"}), 400


        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE emision_avaluo
            SET rfc_firmante = ?, firma_digital = ?, fecha_firmada = ?, cadena_original = ?, nombre_firmante = ?
            WHERE clave_solicitud = ?
        """, (rfc_firmante, firma_digital, fecha_firmada, cadena_original, nombre_firmante, clave_solicitud))

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
    cursor = db.execute('SELECT * FROM emision_avaluo WHERE clave_solicitud = ?', (clave_solicitud,))
    registro = cursor.fetchone()
    if registro is None:
        return "Registro no encontrado", 404
    
    # response = make_response(render_template('resumenFirma.html', clave_solicitud=clave_solicitud))
    response = make_response(render_template('firmadoEmisionAvaluo.html', emision=registro))

    # Evitar cache para que no se pueda regresar a la página anterior con 'atrás'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
    # return render_template('firmadoEmisionAvaluo.html', emision=registro)

@app.route('/resumen_firma/<clave_solicitud>')
@login_required
def resumen_firma(clave_solicitud):
    db = get_db()
    registro = db.execute('SELECT * FROM emision_avaluo WHERE clave_solicitud = ?', (clave_solicitud,)).fetchone()
    if not registro:
        return "Registro no encontrado", 404
    return render_template('resumenFirma.html', registro=registro)

@app.route('/seguimientos')
@login_required
def seguimientos():
    db = get_db()
    cursor = db.execute('SELECT * FROM emision_avaluo ORDER BY ID')
    registros = cursor.fetchall()
    return render_template('seguimientos.html', registros=registros)

def crear_tabla_emision_avaluo():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emision_avaluo (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        clave_solicitud TEXT UNIQUE,
        servidor TEXT NOT NULL,
        valor_terreno REAL NOT NULL,
        perito_avaluo TEXT NOT NULL,
        superficie_metros REAL NOT NULL,
        clave_avaluo_maestro TEXT NOT NULL,
        uso_terreno TEXT NOT NULL,
        archivo_avaluo TEXT NOT NULL,
        hash_archivo TEXT,  -- NUEVA COLUMNA PARA HASH
        rfc_firmante TEXT,
        firma_digital TEXT,
        fecha_firmada TEXT,
        cadena_original TEXT,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        nombre_firmante TEXT
    )
    """)
    db.commit()


from flask import send_from_directory
from werkzeug.utils import safe_join

@app.route('/uploads/<path:filename>')
@login_required
def uploads(filename):
    safe_path = safe_join(app.config['UPLOAD_FOLDER'], filename)
    if not safe_path or not os.path.isfile(safe_path):
        return "Archivo no encontrado", 404

    # La carpeta base para send_from_directory
    directory = os.path.dirname(safe_path)
    # El nombre del archivo (última parte)
    file = os.path.basename(safe_path)

    return send_from_directory(directory, file)

if __name__ == '__main__':
    with app.app_context():
        crear_tabla_emision_avaluo()
    app.run(host='0.0.0.0', port=5050, debug=True)
