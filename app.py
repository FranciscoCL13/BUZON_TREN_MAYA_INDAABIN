import os
import secrets
import base64
import time
import hashlib
import uuid
from datetime import datetime
import pytz

from flask import Flask, render_template, request, session, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from pycfdi_credentials import Certificate

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'kmz', 'kml', 'geojson'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = secrets.token_hex(32)

db = SQLAlchemy(app)

# Modelo
class Trazo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tramos = db.Column(db.String(300))
    archivo = db.Column(db.String(300))
    archivo_uuid = db.Column(db.String(36))
    km_aprox = db.Column(db.Float)
    identificador = db.Column(db.String(100))
    usuario = db.Column(db.String(100))
    fecha_firmada = db.Column(db.String(40))
    firma_digital = db.Column(db.Text)
    hash_archivo = db.Column(db.String(64))  # SHA256 hash

with app.app_context():
    db.create_all()

# Función para archivos válidos
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Calcular hash SHA256 del archivo
def calcular_hash_archivo(ruta):
    with open(ruta, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# Decorador para sesión
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'rfc' not in session:
            return redirect(url_for('mostrar_login'))
        return f(*args, **kwargs)
    return decorated_function

# Sesión y login
@app.route("/", methods=['GET'])
def mostrar_login():
    return render_template("index.html")

@app.route("/", methods=['POST'])
def login():
    data = request.get_json()

    # Lista de RFCs permitidos (mayúsculas, sin espacios)
    rfc_permitidos = {"RORA650121R65", "AETG960812583", "JILE010830512"}

    if data and data.get("salir"):
        session.clear()

    elif (
        'rfc' not in session
        and 'challenge' in session
        and all(k in data for k in ['certificado', 'firma_cadena', 'timestamp'])
        and abs(time.time() - int(data['timestamp'])) <= 300
    ):
        try:
            cert = Certificate(base64.b64decode(data['certificado']))
            rfc_extraido = cert.subject.rfc.upper().strip()  # Limpia y estandariza el RFC

            if rfc_extraido in rfc_permitidos:
                if cert.verify(
                    base64.b64decode(data['firma_cadena']),
                    (f"{data['timestamp']}_{session['challenge']}").encode("utf-8"),
                    "sha256"
                ):
                    session['rfc'] = rfc_extraido
                else:
                    return jsonify({"error": "Firma no válida"}), 400
            else:
                return jsonify({"error": "RFC no autorizado"}), 403

        except Exception as e:
            return jsonify({"error": "Validación fallida", "detalle": str(e)}), 400

    if 'rfc' not in session:
        session['challenge'] = secrets.token_hex(4)

    return jsonify(dict(session))


# Vistas
@app.route("/home", methods=['GET'])
@login_required
def mostrar_home():
    return render_template("home.html")

@app.route("/carga_tramos", methods=['GET'])
@login_required
def carga_tramos():
    return render_template("carga_tramos.html")

@app.route("/formulario", methods=['GET'])
@login_required
def formulario():
    tramos_opciones = [
        "Tramo 1: Palenque – Escárcega (228 km)",
        "Tramo 2: Escárcega – Calkiní (235 km)",
        "Tramo 3: Calkiní – Izamal (172 km)",
        "Tramo 4: Izamal – Cancún (257 km)",
        "Tramo 5 Norte: Cancún – Tulum Norte (~55.65 km)",
        "Tramo 5 Sur: Tulum Sur – Tulum (~55.65 km)",
        "Tramo 6: Tulum – Chetumal (254 km)",
        "Tramo 7: Chetumal - Escárcega (287 km)"
    ]
    return render_template('formulario.html', tramos=tramos_opciones)

@app.route('/registros')
@login_required
def registros():
    todos = Trazo.query.order_by(Trazo.id.asc()).all()
    return render_template('lista-registros.html', registros=todos)

@app.route("/resumen-captura-trazos", methods=['GET'])
@login_required
def mostrar_resumen_trazos():
    return render_template("resumen-captura-trazos.html")

# Paso 1: guardar datos y archivo temporalmente
import uuid  # Asegúrate de tenerlo importado
import hashlib  # Para calcular SHA-256

@app.route("/tramos", methods=['POST'])
@login_required
def guardar_datos_tramos():
    archivo = request.files.get('archivo')
    tramos = request.form.get('tramos')
    km_aprox = request.form.get('km_aprox')
    identificador = request.form.get('identificador')

    if not all([archivo, tramos, km_aprox, identificador]):
        return jsonify({'error': 'Faltan datos'}), 400

    if not allowed_file(archivo.filename):
        return jsonify({'error': 'Tipo de archivo no permitido'}), 400

    filename = secure_filename(archivo.filename)
    archivo_uuid = str(uuid.uuid4())
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], archivo_uuid)
    os.makedirs(folder_path, exist_ok=True)
    ruta = os.path.join(folder_path, filename)
    archivo.save(ruta)

    # 🔐 Calcular hash SHA-256 del archivo subido
    with open(ruta, "rb") as f:
        hash_archivo = hashlib.sha256(f.read()).hexdigest()

    # Guardar todo en sesión
    session["datos_tramo"] = {
        "tramos": tramos,
        "km_aprox": km_aprox,
        "identificador": identificador,
        "archivo_nombre": filename,
        "archivo_uuid": archivo_uuid,
        "archivo_ruta": ruta,
        "hash_archivo": hash_archivo  # <-- Aquí se guarda el hash
    }

    return jsonify({'mensaje': 'Datos temporales guardados'}), 200


@app.route("/tramos/datos", methods=['POST'])
@login_required
def obtener_datos_tramo():
    datos = session.get("datos_tramo")
    if not datos:
        return jsonify({"error": "No hay datos en sesión"}), 404
    return jsonify(datos)

# Paso 2: guardar firma y persistir en DB
@app.route("/tramos/firmado", methods=['POST'])
@login_required
def guardar_firma_tramos():
    data = request.get_json()
    firma_digital = data.get("firma_digital")
    fecha_firmada_raw = data.get("fecha_firmada")
    hash_enviado = data.get("hash_archivo")  # ← recibido desde el frontend

    if not firma_digital or not fecha_firmada_raw or not hash_enviado:
        return jsonify({'error': 'Faltan datos de firma'}), 400

    datos = session.get("datos_tramo")
    if not datos:
        return jsonify({'error': 'No hay datos temporales en sesión'}), 400

    # 1. Calcular hash real del archivo subido
    hash_calculado = calcular_hash_archivo(datos["archivo_ruta"])

    # 2. Comparar con el hash incluido en la cadena firmada
    if hash_calculado != hash_enviado:
        return jsonify({'error': 'El hash del archivo no coincide. Firma inválida o archivo alterado.'}), 400

    # 3. Convertir la fecha firmada a hora local
    try:
        utc_time = datetime.fromisoformat(fecha_firmada_raw.replace("Z", "+00:00"))
        mexico = pytz.timezone("America/Mexico_City")
        fecha_local = utc_time.astimezone(mexico)
        fecha_formateada = fecha_local.strftime("%d-%m-%Y %H:%M:%S")
    except Exception as e:
        return jsonify({'error': f'Fecha inválida: {e}'}), 400

    nuevo_trazo = Trazo(
        tramos=datos["tramos"],
        archivo=datos["archivo_nombre"],
        archivo_uuid=datos["archivo_uuid"],
        km_aprox=float(datos["km_aprox"]),
        identificador=datos["identificador"],
        usuario=session['rfc'],
        firma_digital=firma_digital,
        fecha_firmada=fecha_formateada,
        hash_archivo=hash_calculado
    )

    db.session.add(nuevo_trazo)
    db.session.commit()
    session.pop("datos_tramo", None)

    return jsonify({'mensaje': 'Firma y datos guardados exitosamente', 'trazo_id': nuevo_trazo.id}), 200

# Mostrar resumen de firma con ID único
@app.route("/resumen-firma/<int:trazo_id>", methods=["GET"])
@login_required
def mostrar_resumen_firma_id(trazo_id):
    trazo = Trazo.query.filter_by(id=trazo_id, usuario=session["rfc"]).first()
    if not trazo:
        return redirect("/home")
    return render_template("resumen-firma.html", trazo=trazo)

from flask import send_from_directory

@app.route('/archivo/<uuid>/<nombre>', methods=['GET'])
@login_required
def servir_archivo(uuid, nombre):
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], uuid)
    return send_from_directory(folder_path, nombre, as_attachment=True)

# Ejecutar
if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True, host="0.0.0.0", port=8080)
