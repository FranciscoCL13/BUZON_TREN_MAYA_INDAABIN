from flask import Flask, render_template, g, request, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename
import traceback
from functools import wraps
from flask import session, redirect, url_for
import time
import base64
import secrets
from pycfdi_credentials import Certificate
from ocsp_proxy import validar_ocsp_proxy



app = Flask(__name__)

# Carpeta base del proyecto
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Ruta a la base de datos SQLite (relativa al script)
app.config['DATABASE'] = os.path.join(BASE_DIR, 'instance', 'avaluo.db')

# Carpeta donde se guardan los archivos subidos
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Extensiones permitidas para upload
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


# #endproitnss DE LOGINS
# @app.route("/login", methods=['GET'])
# def login_page():
#     return render_template("login.html")  # tu HTML con nodecfdi.js

# # LOGign de todas mis endpoinsts
# def requierelogin(view_func):
#     @wraps(view_func)
#     def wrapper(*args, **kwargs):
#         if 'rfc' not in session:
#             return redirect(url_for("login_page"))
#         return view_func(*args, **kwargs)
#     return wrapper

# ## peticion POST a /login para procesar autenticacion del .cer y .key

# @app.route("/login", methods=['POST'])
# def login():
#     data = request.get_json()
    
#     if data and data.get("salir"):
#         session.clear()

#     elif 'rfc' not in session and 'challenge' in session and all(k in data for k in ['certificado', 'firma_cadena', 'timestamp']) and abs(time.time() - int(data['timestamp'])) <= 300:
#         try:
#             cert = Certificate(base64.b64decode(data['certificado']))
#             if cert.verify(base64.b64decode(data['firma_cadena']), f"{data['timestamp']}_{session['challenge']}".encode("utf-8"), "sha256"):
#                 ocsp_result = validar_ocsp_proxy(cert.to_pem().decode())

#                 if ocsp_result.get("resultado") == "VALIDO":
#                     session['rfc'] = cert.subject.rfc
#                 else:
#                     return jsonify({
#                         "error": "Certificado no válido",
#                         "detalle": ocsp_result.get("errorMessage", "Certificado inactivo o revocado")
#                     }), 400
#         except Exception as e:
#             return jsonify({"error": "Validación fallida", "detalle": str(e)}), 400

#     if 'rfc' not in session:
#         session['challenge'] = secrets.token_hex(4)

#     return jsonify(dict(session))


#HOEM PRINCIPAL DE MI APTS
@app.route('/home_buzon')
# @requierelogin
def home():
    return render_template('home.html')

@app.route('/buzon')
# @requierelogin
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
# @requierelogin
def emisionAvaluo(clave_solicitud):
    db = get_db()
    cursor = db.execute('SELECT * FROM avaluo_maestro  WHERE clave = ?', (clave_solicitud,))
    avaluo_maestro  = cursor.fetchone()
    if avaluo_maestro  is None:
        return "Tarea no encontrada", 404
    return render_template('emisionAvaluo.html', emisionAvaluo=avaluo_maestro)

@app.route('/emisionAvaluo/guardar', methods=['POST'])
# @requierelogin
def guardar_emision():
    try:
        print("📥 FORM DATA:", dict(request.form))
        print("📎 FILES:", request.files)

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

        # ✅ Validar si ya existe esa clave
        cursor.execute("SELECT id FROM emision_avaluo_v2 WHERE clave_solicitud = ?", (clave_solicitud,))
        existente = cursor.fetchone()
        if existente:
            return jsonify({
                "status": "error",
                "message": f"Ya existe un registro con la clave_solicitud '{clave_solicitud}'"
            }), 409  # HTTP 409 Conflict

        # 📝 Guardar archivo
        filename = secure_filename(archivo_avaluo.filename)
        archivo_avaluo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # 🚀 Insertar nuevo registro
        cursor.execute("""
            INSERT INTO emision_avaluo_v2
            (clave_solicitud, servidor, valor_terreno, perito_avaluo, superficie_metros, clave_avaluo_maestro, uso_terreno, archivo_avaluo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (clave_solicitud, servidor, valor_terreno, perito_avaluo, superficie_metros, clave_avaluo_maestro, uso_terreno, filename))
        db.commit()

        registro_id = cursor.lastrowid
        return jsonify({"status": "ok", "message": "Datos guardados correctamente", "id": registro_id})

    except Exception as e:
        print("❌ ERROR:", str(e))
        traceback.print_exc()
        db.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/emisionAvaluo/firmado', methods=['POST'])
# @requierelogin
def firmado_emision_save():
    try:
        clave_solicitud = request.form.get('clave_solicitud')
        servidor = request.form.get('servidor')
        valor_terreno = request.form.get('valor_terreno')
        perito_avaluo = request.form.get('perito_avaluo')
        superficie_metros = request.form.get('superficie_metros')
        clave_avaluo_maestro = request.form.get('clave_avaluo_maestro')
        uso_terreno = request.form.get('uso_terreno')
        archivo_avaluo = request.form.get('archivo_avaluo')
        rfc_firmante = request.form.get('rfc_firmante')
        firma_digital = request.form.get('firma_digital')
        fecha_firmada = request.form.get('fecha_firmada')
        cadena_original = request.form.get('cadena_original')


        if not all([clave_solicitud, servidor, valor_terreno, perito_avaluo, superficie_metros, clave_avaluo_maestro, uso_terreno, archivo_avaluo, clave_solicitud, rfc_firmante, firma_digital, fecha_firmada, cadena_original]):
            return jsonify({"status": "error", "message": "Faltan datos para guardar la firma"}), 400

        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE emision_avaluo_v2
            SET rfc_firmante = ?, firma_digital = ?, fecha_firmada = ?, cadena_original = ?
            WHERE clave_solicitud = ?
        """, (rfc_firmante, firma_digital, fecha_firmada, cadena_original, clave_solicitud))

        if cursor.rowcount == 0:
            return jsonify({"status": "error", "message": "Registro no encontrado para actualizar firma"}), 404

        db.commit()
        return jsonify({"status": "ok", "message": "Firma guardada correctamente"})

    except Exception as e:
        db.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


# Muestra el formulario y los datos precargados para firma

@app.route('/emisionAvaluo/firmado/<clave_solicitud>')
# @requierelogin
def firmado_emision(clave_solicitud):
    db = get_db()
    cursor = db.execute('SELECT * FROM emision_avaluo_v2 WHERE clave_solicitud = ?', (clave_solicitud,))
    registro = cursor.fetchone()
    if registro is None:
        return "Registro no encontrado", 404
    return render_template('firmadoEmisionAvaluo.html', emision=registro)

# Resumen FIRMA

@app.route('/resumen_firma/<clave_solicitud>')
def resumen_firma(clave_solicitud):
    db = get_db()
    registro = db.execute('SELECT * FROM emision_avaluo_v2 WHERE clave_solicitud = ?', (clave_solicitud,)).fetchone()
    if not registro:
        return "Registro no encontrado", 404

    # Puedes pasar datos si quieres usarlos en el template, por ejemplo:
    # return render_template('resumenFirma.html', registro=registro)

    # Pero si prefieres seguir usando sessionStorage para mostrar datos, sólo envía la clave
    return render_template('resumenFirma.html', clave_solicitud=clave_solicitud)


#MIS SEGUIMIENTOS
@app.route('/seguimientos')
# @requierelogin
def seguimientos():
    db = get_db()
    cursor = db.execute('SELECT * FROM emision_avaluo_v2 ORDER BY ID')
    registros = cursor.fetchall()
    return render_template('seguimientos.html', registros=registros)

# def crear_tabla_emision_avaluo():
#     db = get_db()
#     cursor = db.cursor()
#     cursor.execute("""
#     CREATE TABLE IF NOT EXISTS emision_avaluo (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         clave_solicitud TEXT UNIQUE,
#         servidor TEXT NOT NULL,
#         fuente REAL NOT NULL,
#         costo TEXT NOT NULL,
#         fecha_pago REAL NOT NULL,
#         comprobante_numero TEXT NOT NULL,
#         clc_numero TEXT NOT NULL,
#         archivo_comprobante TEXT NOT NULL,
#         usuario TEXT,
#         firma_digital TEXT,
#         fecha_firmada TEXT,
#         cadena_original TEXT,
#         fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#     )
#     """)
#     db.commit()
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
