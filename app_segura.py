#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app_segura.py — ACTIVIDAD 4 y EJERCICIOS 3.1 / 4.1 de la Guía 04 (ISW, UNSAAC).

Refactorización y hardening de app_vulnerable.py (defensas en profundidad):

  Actividad 4:
    Paso 1 — Consultas parametrizadas (tuplas) en TODA la capa de datos.
    Paso 2 — Validación de propiedad del objeto: si la reserva no es del
             usuario de la sesión → HTTP 403 Forbidden.
    Paso 3 — Salida escapada con markupsafe.escape() (mitigación XSS).
    Paso 4 — Archito guardado como app_segura.py.

  Ejercicio 3.1 — POST /tasks con validación de servidor:
    título obligatorio (3–120), descripción opcional (≤1000), estado en
    {pendiente, en_progreso, completada}, rechazo de campos desconocidos
    (p. ej. role:"admin"), límite de tamaño de solicitud y log de
    advertencia sin guardar el payload (solo regla + parámetro).

  Ejercicio 4.1 — Búsqueda de tareas:
    antes  (inseguro):  "... LIKE '%" + search + "%'"
    después (seguro):   execute("... LIKE ?", (f"%{search}%",))
    más validación de longitud/caracteres y pruebas con comillas,
    cadenas largas, caracteres especiales y nulos.

La autenticación/sesiones de esta entrega corresponden al Ejercicio 1.2 y
viven en app.py (Argon2id, bloqueo progresivo, tokens con TTL). Aquí la
sesión se representa con el token Bearer que app.py emite.

Uso:  python app_segura.py   →  http://127.0.0.1:5003
"""

import os
import re
import sqlite3
import time

from flask import Flask, g, jsonify, request
from markupsafe import escape

DB_PATH = os.environ.get("GUIA4_SEGURA_DB", "guia4_vulnerable.db")

# ---------------------------------------------------------------------------
# Política de validación del Ejercicio 3.1
# ---------------------------------------------------------------------------
TITULO_MIN, TITULO_MAX = 3, 120
DESCRIPCION_MAX = 1000
ESTADOS_VALIDOS = {"pendiente", "en_progreso", "completada"}
CAMPOS_TAREAS = {"titulo", "descripcion", "estado"}          # lista blanca
MAX_CUERPO_BYTES = 16 * 1024                                  # límite 16 KiB
BUSQUEDA_MAX = 60                                             # Ej. 4.1, paso 4
BUSQUEDA_REGEX = re.compile(r"^[\wáéíóúÁÉÍÓÚñÑüÜ .,:;!¡¿?()\-]+$", re.UNICODE)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CUERPO_BYTES


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def cerrar_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT NOT NULL UNIQUE,
            nombre        TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            rol           TEXT NOT NULL DEFAULT 'estudiante',
            creado_en     REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            expira_en  REAL NOT NULL,
            revocada   INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS reservas (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            cancha  TEXT NOT NULL,
            fecha   TEXT NOT NULL,
            estado  TEXT NOT NULL DEFAULT 'confirmada'
        );
        CREATE TABLE IF NOT EXISTS comentarios (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            contenido  TEXT NOT NULL,
            creado_en  REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id    INTEGER NOT NULL REFERENCES users(id),
            titulo      TEXT NOT NULL,
            descripcion TEXT NOT NULL DEFAULT '',
            estado      TEXT NOT NULL DEFAULT 'pendiente'
                        CHECK (estado IN ('pendiente','en_progreso','completada')),
            creado_en   REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      REAL NOT NULL,
            evento  TEXT NOT NULL,
            user_id INTEGER,
            ip      TEXT NOT NULL,
            detalle TEXT NOT NULL DEFAULT ''
        );
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Utilidades de seguridad
# ---------------------------------------------------------------------------
def _audit(evento: str, user_id=None, detalle: str = "") -> None:
    """Log de auditoría. El detalle NUNCA incluye el payload del usuario:
    solo la regla de detección y el nombre del parámetro (recomendación OWASP
    para evitar inyección en logs)."""
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (ts, evento, user_id, ip, detalle) VALUES (?,?,?,?,?)",
        (time.time(), evento, user_id, request.remote_addr or "?", detalle),
    )
    db.commit()


def _sesion_actual():
    """Resuelve el user_id desde el token Bearer (hash almacenado por app.py).

    Devuelve None si falta el token, es desconocido o la sesión expiró/está
    revocada. La emisión del token es responsabilidad de app.py (Ejercicio 1.2).
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    import hashlib
    token_hash = hashlib.sha256(auth[7:].encode("utf-8")).hexdigest()
    fila = get_db().execute(
        "SELECT user_id FROM sessions WHERE token_hash = ? AND revocada = 0 "
        "AND expira_en > ?",
        (token_hash, time.time()),
    ).fetchone()
    return fila["user_id"] if fila else None


def _requiere_sesion(f):
    from functools import wraps

    @wraps(f)
    def envoltura(*args, **kwargs):
        user_id = _sesion_actual()
        if user_id is None:
            return jsonify({"error": "Sesión inválida o expirada."}), 401
        return f(user_id, *args, **kwargs)

    return envoltura


# ---------------------------------------------------------------------------
# ACTIVIDAD 4, PASO 2 — IDOR corregido: propiedad verificada en el servidor
# ---------------------------------------------------------------------------
@app.get("/reservas")
@_requiere_sesion
def obtener_reserva(user_id):
    """Entrega la reserva SOLO si pertenece al usuario de la sesión.

    Antes (app_vulnerable.py): el id se usaba sin filtro de propiedad y
    cualquiera podía leer /reservas?id=105. Ahora la consulta incluye al
    dueño Y, además, se verifica tras la lectura (defensa en profundidad):
    si la reserva existe pero no es del solicitante → HTTP 403 Forbidden,
    sin exponer ningún dato.
    """
    reserva_id = request.args.get("id", "")
    if not reserva_id.isdigit():
        return jsonify({"error": "Solicitud inválida."}), 400
    db = get_db()
    # PASO 1: consulta parametrizada (tupla) — nunca concatenación.
    fila = db.execute(
        "SELECT id, user_id, cancha, fecha, estado FROM reservas "
        "WHERE id = ? AND user_id = ?",
        (int(reserva_id), user_id),
    ).fetchone()
    if fila is None:
        # ¿existe la reserva pero de otro dueño? → 403, no 404, para no
        # confirmar su existencia (y registrar el intento).
        ajena = db.execute(
            "SELECT 1 FROM reservas WHERE id = ?", (int(reserva_id),)
        ).fetchone()
        if ajena:
            _audit("acceso_no_autorizado_reserva", user_id,
                   f"regla=propiedad_recurso parametro=id")
            return jsonify({"error": "Forbidden"}), 403
        return jsonify({"error": "Reserva no encontrada"}), 404
    return jsonify(dict(fila))


# ---------------------------------------------------------------------------
# ACTIVIDAD 4, PASO 1 — SQLi corregido: búsqueda parametrizada
# ---------------------------------------------------------------------------
@app.get("/api/buscar")
def buscar_usuario():
    """Busca usuarios por correo con consulta parametrizada.

    Antes:  consulta = "... email = '" + email + "'"
    Ahora:  execute("... email = ?", (email,))  — el valor viaja como DATO,
    nunca como parte del comando, y la entrada se valida antes.
    """
    email = request.args.get("email", "")
    if len(email) > 254 or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""):
        _audit("validacion_fallida", None, "regla=email_invalido parametro=email")
        return jsonify({"error": "Parámetro inválido."}), 400
    db = get_db()
    filas = db.execute(
        "SELECT id, email, nombre, rol FROM users WHERE email = ?", (email,)
    ).fetchall()
    return jsonify([dict(f) for f in filas])


# ---------------------------------------------------------------------------
# ACTIVIDAD 4, PASO 3 — XSS corregido: salida escapada con markupsafe
# ---------------------------------------------------------------------------
@app.get("/api/comentarios")
def listar_comentarios():
    """Devuelve los comentarios con el contenido escapado.

    Antes: el texto del usuario se devolvía tal cual y un <script> insertado
    se ejecutaba en el navegador de la víctima. Ahora todo valor dinámico se
    envuelve en escape(): los caracteres < > & " ' se convierten en
    entidades HTML (&lt;script&gt;...) y se muestran como texto inofensivo.
    """
    db = get_db()
    filas = db.execute(
        "SELECT id, user_id, contenido, creado_en FROM comentarios ORDER BY id DESC"
    ).fetchall()
    return jsonify([
        {
            "id": f["id"],
            "user_id": f["user_id"],
            # PASO 3: escapado contextual de la salida
            "contenido": str(escape(f["contenido"])),
            "creado_en": f["creado_en"],
        }
        for f in filas
    ])


@app.post("/api/comentarios")
def crear_comentario():
    """Guarda el comentario validando tipo y longitud (la salida se escapa
    al LEER, que es donde el navegador la interpreta)."""
    data = request.get_json(force=True, silent=True) or {}
    contenido = data.get("contenido", "")
    if not isinstance(contenido, str) or not (1 <= len(contenido) <= 1000):
        _audit("validacion_fallida", None, "regla=longitud_campo parametro=contenido")
        return jsonify({"error": "Campo inválido."}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO comentarios (user_id, contenido, creado_en) VALUES (?,?,?)",
        (data.get("user_id", 1), contenido, time.time()),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid}), 201


# ---------------------------------------------------------------------------
# EJERCICIO 3.1 — POST /tasks con validación robusta en el servidor
# ---------------------------------------------------------------------------
@app.post("/tasks")
@_requiere_sesion
def crear_tarea(user_id):
    """Crea una tarea SOLO con campos válidos; rechaza todo lo demás.

    Reglas (Ejercicio 3.1, paso 3):
      • titulo      obligatorio, 3–120 caracteres.
      • descripcion opcional, máximo 1000.
      • estado      solo pendiente | en_progreso | completada.
      • Campos desconocidos → 400 (p. ej. un inyectado role:"admin").
      • Límite de tamaño de solicitud (MAX_CONTENT_LENGTH, 16 KiB).
    """
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        _audit("validacion_fallida", user_id, "regla=cuerpo_no_json parametro=body")
        return jsonify({"error": "Cuerpo inválido."}), 400

    # Rechazo de campos desconocidos / mass assignment
    desconocidos = set(data) - CAMPOS_TAREAS
    if desconocidos:
        _audit("validacion_fallida", user_id,
               "regla=campo_desconocido parametro=" + ",".join(sorted(desconocidos)))
        return jsonify({"error": "Campos no permitidos."}), 400

    titulo = data.get("titulo")
    if not isinstance(titulo, str) or not (TITULO_MIN <= len(titulo.strip()) <= TITULO_MAX):
        _audit("validacion_fallida", user_id, "regla=rango_longitud parametro=titulo")
        return jsonify({"error": "Título inválido (3–120 caracteres)."}), 400

    descripcion = data.get("descripcion", "")
    if not isinstance(descripcion, str) or len(descripcion) > DESCRIPCION_MAX:
        _audit("validacion_fallida", user_id, "regla=rango_longitud parametro=descripcion")
        return jsonify({"error": "Descripción inválida (máx. 1000)."}), 400

    estado = data.get("estado", "pendiente")
    if estado not in ESTADOS_VALIDOS:
        _audit("validacion_fallida", user_id, "regla=valor_no_permitido parametro=estado")
        return jsonify({"error": "Estado inválido."}), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO tasks (owner_id, titulo, descripcion, estado, creado_en) "
        "VALUES (?,?,?,?,?)",
        (user_id, titulo.strip(), descripcion, estado, time.time()),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "estado": estado}), 201


# ---------------------------------------------------------------------------
# EJERCICIO 4.1 — Búsqueda de tareas: antes (inseguro) vs. después (seguro)
# ---------------------------------------------------------------------------
def buscar_tareas_INSEGURA(search: str):
    """ANTES — concatenación de cadenas (NO USAR; solo para comparación).

    query = "SELECT ... WHERE titulo LIKE '%" + search + "%'"

    ¿Por qué es peligroso? search lo controla el usuario: un valor como
    %'; DROP TABLE tasks; -- altera la ESTRUCTURA de la consulta, porque el
    motor no distingue comando de dato cuando se concatenan.
    """
    db = get_db()
    query = ("SELECT id, owner_id, titulo FROM tasks WHERE titulo LIKE '%"  # nosec B608 ; concat intencional (réplica "antes" del Ej. 4.1, no expuesta por HTTP)
             + search + "%'")
    return db.execute(query).fetchall()


@app.get("/api/tasks/buscar")
@_requiere_sesion
def buscar_tareas(user_id):
    """DESPUÉS — consulta parametrizada + validación del parámetro.

    El comodín % se añade del lado del servidor (f"%{search}%") y viaja como
    DATO en la tupla; el usuario no puede cerrar la cadena ni inyectar SQL.
    Además (paso 4): longitud máxima 60 y lista de caracteres permitidos.
    """
    search = request.args.get("q", "")
    if not isinstance(search, str) or len(search) > BUSQUEDA_MAX:
        _audit("validacion_fallida", user_id, "regla=longitud_maxima parametro=q")
        return jsonify({"error": "Parámetro demasiado largo."}), 400
    if search and not BUSQUEDA_REGEX.match(search):
        _audit("validacion_fallida", user_id, "regla=caracteres_permitidos parametro=q")
        return jsonify({"error": "Parámetro con caracteres no permitidos."}), 400

    db = get_db()
    filas = db.execute(
        "SELECT id, owner_id, titulo, estado FROM tasks "
        "WHERE owner_id = ? AND titulo LIKE ? ORDER BY id DESC LIMIT 50",
        (user_id, f"%{search}%"),          # ← parametrizado, nunca concatenación
    ).fetchall()
    return jsonify([dict(f) for f in filas])


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5003, debug=False)
