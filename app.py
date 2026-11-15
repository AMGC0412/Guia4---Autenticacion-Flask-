# -*- coding: utf-8 -*-
"""
GUÍA DE PRÁCTICA 04 – INGENIERÍA DE SOFTWARE SEGURO
Ejercicio Propuesto 1.2: Implementar autenticación resistente a ataques comunes.

API de gestión de tareas con autenticación segura.
Stack: Python 3 / Flask / SQLite / Argon2id.

Controles implementados (mapeo con los pasos de la guía):
  (1)  Registro e inicio de sesión.......................... /api/auth/register, /api/auth/login
  (2)  Hash lento moderno Argon2id (no MD5/SHA-1/SHA-256)... _hash_password() / _verify_password()
  (3a) Límite de intentos fallidos por cuenta y por IP...... _check_lockout() / _register_failure()
  (3b) Bloqueo temporal progresivo (30 s → 60 s → 120 s...).. lockout_seconds()
  (3c) Mensajes genéricos de error (sin enumerar usuarios).. MSG_CREDENCIALES_INVALIDAS
  (3d) Tokens de sesión con expiración (TTL configurable)... _issue_session() / @requiere_sesion
  (3e) Revocación de sesión al cambiar contraseña............ /api/auth/password/change
  (3f) Regeneración del identificador de sesión tras login.. cada login emite un token nuevo
  (4a) Token de restablecimiento de un solo uso.............. /api/auth/reset
  (4b) Expiración corta del token (15 minutos)............... RESET_TTL
  (4c) Invalidación de tokens anteriores..................... /api/auth/forgot
  (4d) Registro del evento sin exponer el token.............. _audit() + audit_logs
  (5)  Toda consulta SQL usa parámetros (sin concatenación).. cursor.execute(sql, (params,))

Ejecución:  python app.py       (por defecto escucha en http://127.0.0.1:5000)
Pruebas:    pytest -v
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from flask import Flask, g, jsonify, request, current_app

# ---------------------------------------------------------------------------
# Constantes de seguridad
# ---------------------------------------------------------------------------
MAX_INTENTOS_LOGIN = 5          # intentos fallidos permitidos antes del bloqueo
BLOQUEO_BASE_SEG = 30           # primer bloqueo: 30 s; luego se duplica progresivamente
BLOQUEO_MAX_SEG = 900           # techo del bloqueo: 15 min
VENTANA_INTENTOS_SEG = 900      # los fallos "envejecen" a los 15 min
SESSION_TTL_SEG = 900           # vida del token de sesión: 15 min
RESET_TTL_SEG = 900             # vida del token de restablecimiento: 15 min
MAX_CUERPO_BYTES = 16 * 1024    # límite de tamaño de solicitud: 16 KiB

ROL_DEFECTO = "estudiante"      # el rol NUNCA llega del cliente

MSG_CREDENCIALES_INVALIDAS = "Credenciales inválidas."
MSG_RESET_ENVIADO = ("Si el correo está registrado, se envió un enlace "
                     "de restablecimiento.")
MSG_TOKEN_INVALIDO = "Token inválido o expirado."
MSG_SESION_INVALIDA = "Sesión inválida o expirada."

# Argon2id: función de derivación de claves lenta y con memoria.
# time_cost=3, memory_cost=64 MiB, parallelism=4 (valores por defecto de OWASP).
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

REGEX_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
# Utilidades criptográficas
# ---------------------------------------------------------------------------
def _hash_password(plain: str) -> str:
    """Devuelve el hash Argon2id (con sal aleatoria incorporada) de la contraseña."""
    return HASHER.hash(plain)


def _verify_password(hash_guardado: str, plain: str) -> bool:
    """Verifica la contraseña contra el hash Argon2id almacenado."""
    try:
        return HASHER.verify(hash_guardado, plain)
    except (VerifyMismatchError, InvalidHashError):
        return False


def _token_hash(token: str) -> str:
    """
    SHA-256 del token para almacenamiento/consulta.
    Nota: SHA-256 es aceptable aquí porque el token tiene alta entropía
    (256 bits de aleatoriedad de secrets); NO se usa para contraseñas.
    """
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _nuevo_token() -> str:
    """Token criptográficamente seguro (256 bits) para sesiones y resets."""
    return secrets.token_urlsafe(32)


def _client_ip() -> str:
    """IP del cliente (header de prueba X-Forwarded-For o remote_addr)."""
    return (request.headers.get("X-Forwarded-For", request.remote_addr or "?")
            .split(",")[0].strip())


# ---------------------------------------------------------------------------
# Política de contraseñas (validación en SERVIDOR)
# ---------------------------------------------------------------------------
def validar_password(password: str) -> str | None:
    """Devuelve None si la contraseña cumple la política; si no, el motivo."""
    if not isinstance(password, str) or len(password) < 10:
        return "La contraseña debe tener al menos 10 caracteres."
    if not re.search(r"[A-Z]", password):
        return "La contraseña debe incluir al menos una mayúscula."
    if not re.search(r"[a-z]", password):
        return "La contraseña debe incluir al menos una minúscula."
    if not re.search(r"\d", password):
        return "La contraseña debe incluir al menos un dígito."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "La contraseña debe incluir al menos un símbolo."
    return None


# ---------------------------------------------------------------------------
# Bloqueo temporal progresivo
# ---------------------------------------------------------------------------
def lockout_seconds(intentos_fallidos: int) -> int:
    """
    Duración del bloqueo según el número de fallos acumulados:
    5 fallos → 30 s; 6 → 60 s; 7 → 120 s; ... tope 900 s (15 min).
    """
    if intentos_fallidos < MAX_INTENTOS_LOGIN:
        return 0
    return min(BLOQUEO_BASE_SEG * 2 ** (intentos_fallidos - MAX_INTENTOS_LOGIN),
               BLOQUEO_MAX_SEG)


# ---------------------------------------------------------------------------
# Fábrica de la aplicación
# ---------------------------------------------------------------------------
def create_app(db_path: str | None = None,
               session_ttl: int = SESSION_TTL_SEG) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CUERPO_BYTES
    app.config["SESSION_TTL"] = session_ttl
    # Buzón simulado: en producción aquí se conectaría un servicio SMTP.
    # El token de reset SOLO vive en este "buzón", nunca en la respuesta HTTP.
    app.email_outbox = []

    if db_path is None:
        db_path = os.environ.get("GUIA4_DB",
                                 os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                              "guia4.db"))
    app.config["DB_PATH"] = db_path

    # ------------------------------------------------------------------ DB --
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def _cerrar_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db() -> None:
        db = sqlite3.connect(app.config["DB_PATH"])
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
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                creada_en  REAL NOT NULL,
                expira_en  REAL NOT NULL,
                revocada   INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                identifier  TEXT NOT NULL,   -- email normalizado o '*' (regla por IP)
                ip          TEXT NOT NULL,   -- IP del cliente o '*' (regla por cuenta)
                intentos    INTEGER NOT NULL DEFAULT 0,
                bloqueada_hasta REAL NOT NULL DEFAULT 0,
                ultimo_intento REAL NOT NULL DEFAULT 0,
                PRIMARY KEY (identifier, ip)
            );
            CREATE TABLE IF NOT EXISTS password_resets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                creado_en  REAL NOT NULL,
                expira_en  REAL NOT NULL,
                usado      INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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

    init_db()

    # ------------------------------------------------------------- auditoría --
    def _audit(evento: str, user_id: int | None, detalle: str = "") -> None:
        """
        Registra un evento de auditoría SIN datos sensibles:
        nunca se guardan contraseñas ni tokens, solo el tipo de evento,
        el usuario (si se conoce) y la IP de origen.
        """
        db = get_db()
        db.execute(
            "INSERT INTO audit_logs (ts, evento, user_id, ip, detalle) "
            "VALUES (?, ?, ?, ?, ?)",
            (time.time(), evento, user_id, _client_ip(), detalle),
        )
        db.commit()

    # ------------------------------------------------------ bloqueo de login --
    def _check_lockout(email_key: str, ip: str) -> int:
        """
        Devuelve los segundos restantes de bloqueo (0 = sin bloqueo).
        Evalúa la regla por CUENTA (email, '*') y la regla por IP ('*', ip).
        Los contadores con más de VENTANA_INTENTOS_SEG sin actividad se reinician.
        """
        db = get_db()
        ahora = time.time()
        restante = 0
        for identifier, ip_col in ((email_key, "*"), ("*", ip)):
            fila = db.execute(
                "SELECT intentos, bloqueada_hasta, ultimo_intento "
                "FROM login_attempts WHERE identifier = ? AND ip = ?",
                (identifier, ip_col),
            ).fetchone()
            if fila is None:
                continue
            if ahora - fila["ultimo_intento"] > VENTANA_INTENTOS_SEG:
                # El contador envejeció: se reinicia (decaimiento natural).
                db.execute(
                    "UPDATE login_attempts SET intentos = 0, bloqueada_hasta = 0 "
                    "WHERE identifier = ? AND ip = ?",
                    (identifier, ip_col),
                )
                db.commit()
                continue
            restante = max(restante, fila["bloqueada_hasta"] - ahora)
        return max(0, int(restante))

    def _register_failure(email_key: str, ip: str) -> int:
        """Cuenta un fallo en las reglas por cuenta y por IP; devuelve el bloqueo."""
        db = get_db()
        ahora = time.time()
        bloqueo = 0
        for identifier, ip_col in ((email_key, "*"), ("*", ip)):
            db.execute(
                "INSERT INTO login_attempts (identifier, ip, intentos, ultimo_intento) "
                "VALUES (?, ?, 1, ?) "
                "ON CONFLICT(identifier, ip) DO UPDATE SET "
                "intentos = intentos + 1, ultimo_intento = excluded.ultimo_intento",
                (identifier, ip_col, ahora),
            )
            fila = db.execute(
                "SELECT intentos FROM login_attempts WHERE identifier = ? AND ip = ?",
                (identifier, ip_col),
            ).fetchone()
            bloqueo = lockout_seconds(fila["intentos"])
            if bloqueo:
                db.execute(
                    "UPDATE login_attempts SET bloqueada_hasta = ? "
                    "WHERE identifier = ? AND ip = ?",
                    (ahora + bloqueo, identifier, ip_col),
                )
        db.commit()
        return bloqueo

    def _clear_failures(email_key: str, ip: str) -> None:
        db = get_db()
        db.execute("DELETE FROM login_attempts WHERE identifier = ?", (email_key,))
        db.execute("DELETE FROM login_attempts WHERE ip = ? AND identifier = '*'", (ip,))
        db.commit()

    # ----------------------------------------------------------- sesiones --
    def _issue_session(user_id: int) -> tuple[str, float]:
        """
        Emite un token de sesión NUEVO (regeneración del identificador tras
        cada login: defensa contra fijación de sesión) y lo guarda hasheado
        con su fecha de expiración.
        """
        token = _nuevo_token()
        ahora = time.time()
        expira = ahora + app.config["SESSION_TTL"]
        db = get_db()
        db.execute(
            "INSERT INTO sessions (token_hash, user_id, creada_en, expira_en) "
            "VALUES (?, ?, ?, ?)",
            (_token_hash(token), user_id, ahora, expira),
        )
        db.commit()
        return token, expira

    def _revoke_all_sessions(user_id: int) -> None:
        """Revoca todas las sesiones activas de un usuario (cambio de contraseña/reset)."""
        db = get_db()
        db.execute("UPDATE sessions SET revocada = 1 WHERE user_id = ?", (user_id,))
        db.commit()

    def _usuario_de_sesion() -> sqlite3.Row | None:
        """Valida el token Bearer: existe, no revocado y no expirado."""
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[len("Bearer "):].strip()
        db = get_db()
        fila = db.execute(
            "SELECT u.*, s.expira_en, s.id AS session_id "
            "FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ? AND s.revocada = 0",
            (_token_hash(token),),
        ).fetchone()
        if fila is None or fila["expira_en"] <= time.time():
            return None
        return fila

    def requiere_sesion(f):
        """Decorador: exige un token de sesión válido y no expirado."""
        @wraps(f)
        def wrapper(*args, **kwargs):
            usuario = _usuario_de_sesion()
            if usuario is None:
                return jsonify({"error": MSG_SESION_INVALIDA}), 401
            return f(usuario, *args, **kwargs)
        return wrapper

    # --------------------------------------------------- cabeceras seguras --
    @app.after_request
    def _cabeceras_seguras(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    # =====================================================================
    # ENDPOINTS DE AUTENTICACIÓN
    # =====================================================================

    @app.post("/api/auth/register")
    def register():
        datos = request.get_json(silent=True)
        if not isinstance(datos, dict):
            return jsonify({"error": "Cuerpo JSON inválido."}), 400

        # Lista blanca de campos: se rechazan campos desconocidos (ej. role=admin).
        permitidos = {"email", "password", "nombre"}
        desconocidos = set(datos) - permitidos
        if desconocidos:
            return jsonify({"error": "Campo no permitido.",
                            "campo": sorted(desconocidos)[0]}), 400

        email = str(datos.get("email", "")).strip().lower()
        password = datos.get("password")
        nombre = str(datos.get("nombre", "")).strip()

        if not REGEX_EMAIL.match(email):
            return jsonify({"error": "Correo con formato inválido."}), 400
        if not nombre or len(nombre) > 80:
            return jsonify({"error": "El nombre es obligatorio (máx. 80 caracteres)."}), 400
        motivo = validar_password(password)
        if motivo:
            return jsonify({"error": motivo}), 400

        db = get_db()
        existe = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
        if existe:
            return jsonify({"error": "No se pudo completar el registro."}), 409

        db.execute(
            "INSERT INTO users (email, nombre, password_hash, rol, creado_en) "
            "VALUES (?, ?, ?, ?, ?)",
            (email, nombre, _hash_password(password), ROL_DEFECTO, time.time()),
        )
        db.commit()
        _audit("registro_ok", db.execute("SELECT id FROM users WHERE email = ?",
                                         (email,)).fetchone()["id"])
        return jsonify({"mensaje": "Usuario registrado correctamente."}), 201

    @app.post("/api/auth/login")
    def login():
        datos = request.get_json(silent=True)
        if not isinstance(datos, dict):
            return jsonify({"error": MSG_CREDENCIALES_INVALIDAS}), 400

        email = str(datos.get("email", "")).strip().lower()
        password = datos.get("password", "")
        ip = _client_ip()

        # 1) ¿Cuenta o IP bloqueadas? (se evalúa ANTES de verificar credenciales)
        restante = _check_lockout(email, ip)
        if restante > 0:
            resp = jsonify({"error": "Demasiados intentos fallidos. "
                                     "Intente más tarde."})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(restante)
            return resp

        db = get_db()
        usuario = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        # 2) Verificación con tiempo constante para no filtrar si el usuario existe.
        hash_objetivo = (usuario["password_hash"] if usuario
                         else "$argon2id$v=19$m=65536,t=3,p=4$"
                            "c2FsdGVfcXVlX2FpbXNfYXRfY29uc3RhbnRfdGltZQ$"
                            "aGFzaF9kZV9wb2xiYV9kZV9jb21wYXJhY2lvbl9zaW11bGFkYQ")
        credenciales_ok = _verify_password(hash_objetivo, password or "") and usuario

        if not credenciales_ok:
            bloqueo = _register_failure(email, ip)
            _audit("login_fallido", usuario["id"] if usuario else None,
                   "credenciales inválidas (sin datos sensibles)")
            if bloqueo:
                _audit("cuenta_o_ip_bloqueada", usuario["id"] if usuario else None,
                       f"bloqueo {bloqueo} s")
                resp = jsonify({"error": "Demasiados intentos fallidos. Intente más tarde."})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(bloqueo)
                return resp
            # Mensaje genérico: no revela si el correo existe.
            return jsonify({"error": MSG_CREDENCIALES_INVALIDAS}), 401

        # 3) Éxito: limpiar contadores, regenerar identificador de sesión y auditar.
        _clear_failures(email, ip)
        token, expira = _issue_session(usuario["id"])
        _audit("login_ok", usuario["id"])
        return jsonify({
            "token": token,
            "token_type": "Bearer",
            "expira_en": expira,
        }), 200

    @app.post("/api/auth/logout")
    @requiere_sesion
    def logout(usuario):
        # Revoca la sesión actual (el token deja de ser válido de inmediato).
        token = request.headers["Authorization"][len("Bearer "):].strip()
        db = get_db()
        db.execute("UPDATE sessions SET revocada = 1 WHERE token_hash = ?",
                   (_token_hash(token),))
        db.commit()
        _audit("logout", usuario["id"])
        return jsonify({"mensaje": "Sesión cerrada."}), 200

    @app.get("/api/me")
    @requiere_sesion
    def me(usuario):
        return jsonify({
            "id": usuario["id"],
            "email": usuario["email"],
            "nombre": usuario["nombre"],
            "rol": usuario["rol"],          # el rol SIEMPRE proviene del servidor
            "expira_en": usuario["expira_en"],
        }), 200

    # ------------------------------------------------ cambio de contraseña --
    @app.post("/api/auth/password/change")
    @requiere_sesion
    def password_change(usuario):
        datos = request.get_json(silent=True)
        if not isinstance(datos, dict):
            return jsonify({"error": "Cuerpo JSON inválido."}), 400
        actual = datos.get("password_actual", "")
        nueva = datos.get("password_nueva", "")

        if not _verify_password(usuario["password_hash"], actual or ""):
            return jsonify({"error": MSG_CREDENCIALES_INVALIDAS}), 401
        motivo = validar_password(nueva)
        if motivo:
            return jsonify({"error": motivo}), 400

        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (_hash_password(nueva), usuario["id"]))
        # Revocación de TODAS las sesiones al cambiar la contraseña.
        _revoke_all_sessions(usuario["id"])
        db.commit()
        _audit("password_cambiada", usuario["id"], "todas las sesiones revocadas")
        return jsonify({"mensaje": "Contraseña actualizada. Inicie sesión nuevamente."}), 200

    # ------------------------------------- restablecimiento de contraseña --
    @app.post("/api/auth/forgot")
    def forgot():
        datos = request.get_json(silent=True)
        email = str((datos or {}).get("email", "")).strip().lower()
        ip = _client_ip()

        # Respuesta SIEMPRE idéntica: evita enumeración de usuarios.
        respuesta = jsonify({"mensaje": MSG_RESET_ENVIADO}), 200

        db = get_db()
        usuario = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if usuario is None:
            _audit("reset_solicitado", None, "correo no registrado (respuesta genérica)")
            return respuesta

        # Invalidación de tokens anteriores.
        db.execute("UPDATE password_resets SET usado = 1 WHERE user_id = ? AND usado = 0",
                   (usuario["id"],))
        # Token aleatorio de un solo uso con expiración corta.
        token = _nuevo_token()
        ahora = time.time()
        db.execute(
            "INSERT INTO password_resets (user_id, token_hash, creado_en, expira_en) "
            "VALUES (?, ?, ?, ?)",
            (usuario["id"], _token_hash(token), ahora, ahora + RESET_TTL_SEG),
        )
        db.commit()
        # Auditoría del evento SIN exponer el token.
        _audit("reset_solicitado", usuario["id"], "token de un solo uso emitido")

        # Envío simulado: el token solo vive en el "buzón", no en la respuesta HTTP.
        current_app.email_outbox.append({
            "para": usuario["email"],
            "asunto": "Restablecimiento de contraseña (válido 15 minutos)",
            "enlace": f"https://api.sportreserve.example/reset?token={token}",
        })
        return respuesta

    @app.post("/api/auth/reset")
    def reset():
        datos = request.get_json(silent=True)
        if not isinstance(datos, dict):
            return jsonify({"error": MSG_TOKEN_INVALIDO}), 400
        token = str(datos.get("token", ""))
        nueva = datos.get("password", "")

        db = get_db()
        fila = db.execute(
            "SELECT * FROM password_resets WHERE token_hash = ? AND usado = 0",
            (_token_hash(token),),
        ).fetchone()

        # Un solo uso + expiración corta; mensaje genérico en ambos casos.
        if fila is None or fila["expira_en"] <= time.time():
            _audit("reset_token_invalido", fila["user_id"] if fila else None,
                   "token reutilizado, inválido o expirado")
            return jsonify({"error": MSG_TOKEN_INVALIDO}), 400

        motivo = validar_password(nueva)
        if motivo:
            return jsonify({"error": motivo}), 400

        db.execute("UPDATE password_resets SET usado = 1 WHERE id = ?", (fila["id"],))
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (_hash_password(nueva), fila["user_id"]))
        # El restablecimiento también revoca todas las sesiones activas.
        _revoke_all_sessions(fila["user_id"])
        db.commit()
        _audit("reset_ok", fila["user_id"], "contraseña restablecida; sesiones revocadas")
        return jsonify({"mensaje": "Contraseña restablecida. Inicie sesión nuevamente."}), 200

    # =====================================================================
    # ENDPOINTS DE TAREAS (autorización por propiedad → mitiga IDOR)
    # =====================================================================

    @app.get("/api/tasks")
    @requiere_sesion
    def listar_tareas(usuario):
        db = get_db()
        tareas = db.execute(
            "SELECT id, titulo, descripcion, estado, creado_en FROM tasks "
            "WHERE owner_id = ? ORDER BY id", (usuario["id"],)
        ).fetchall()
        return jsonify([dict(t) for t in tareas]), 200

    @app.post("/api/tasks")
    @requiere_sesion
    def crear_tarea(usuario):
        datos = request.get_json(silent=True)
        if not isinstance(datos, dict):
            return jsonify({"error": "Cuerpo JSON inválido."}), 400
        permitidos = {"titulo", "descripcion", "estado"}
        if set(datos) - permitidos:
            return jsonify({"error": "Campo no permitido."}), 400
        titulo = str(datos.get("titulo", "")).strip()
        if not (3 <= len(titulo) <= 120):
            return jsonify({"error": "El título debe tener entre 3 y 120 caracteres."}), 400
        descripcion = str(datos.get("descripcion", ""))
        if len(descripcion) > 1000:
            return jsonify({"error": "La descripción admite máximo 1000 caracteres."}), 400
        estado = datos.get("estado", "pendiente")
        if estado not in ("pendiente", "en_progreso", "completada"):
            return jsonify({"error": "Estado inválido."}), 400

        db = get_db()
        cur = db.execute(
            "INSERT INTO tasks (owner_id, titulo, descripcion, estado, creado_en) "
            "VALUES (?, ?, ?, ?, ?)",
            (usuario["id"], titulo, descripcion, estado, time.time()),
        )
        db.commit()
        return jsonify({"id": cur.lastrowid, "mensaje": "Tarea creada."}), 201

    def _tarea_propia_o_403(usuario, tarea_id):
        """Autorización en SERVIDOR por propiedad del recurso (mitigación IDOR)."""
        db = get_db()
        tarea = db.execute("SELECT * FROM tasks WHERE id = ?", (tarea_id,)).fetchone()
        if tarea is None:
            return None, (jsonify({"error": "Recurso no encontrado."}), 404)
        if tarea["owner_id"] != usuario["id"]:
            _audit("acceso_denegado_idor", usuario["id"],
                   f"tarea {tarea_id} de otro usuario")
            return None, (jsonify({"error": "Acceso denegado a este recurso."}), 403)
        return tarea, None

    @app.patch("/api/tasks/<int:tarea_id>")
    @requiere_sesion
    def editar_tarea(usuario, tarea_id):
        tarea, error = _tarea_propia_o_403(usuario, tarea_id)
        if error:
            return error
        datos = request.get_json(silent=True) or {}
        campos, valores = [], []
        if "titulo" in datos:
            titulo = str(datos["titulo"]).strip()
            if not (3 <= len(titulo) <= 120):
                return jsonify({"error": "El título debe tener entre 3 y 120 caracteres."}), 400
            campos.append("titulo = ?"); valores.append(titulo)
        if "descripcion" in datos:
            if len(str(datos["descripcion"])) > 1000:
                return jsonify({"error": "La descripción admite máximo 1000 caracteres."}), 400
            campos.append("descripcion = ?"); valores.append(str(datos["descripcion"]))
        if "estado" in datos:
            if datos["estado"] not in ("pendiente", "en_progreso", "completada"):
                return jsonify({"error": "Estado inválido."}), 400
            campos.append("estado = ?"); valores.append(datos["estado"])
        if not campos:
            return jsonify({"error": "Nada que actualizar."}), 400
        valores.append(tarea_id)
        db = get_db()
        # Consulta parametrizada también en la actualización dinámica.
        db.execute(f"UPDATE tasks SET {', '.join(campos)} WHERE id = ?", valores)
        db.commit()
        return jsonify({"mensaje": "Tarea actualizada."}), 200

    @app.delete("/api/tasks/<int:tarea_id>")
    @requiere_sesion
    def eliminar_tarea(usuario, tarea_id):
        tarea, error = _tarea_propia_o_403(usuario, tarea_id)
        if error:
            return error
        db = get_db()
        db.execute("DELETE FROM tasks WHERE id = ?", (tarea_id,))
        db.commit()
        _audit("tarea_eliminada", usuario["id"], f"tarea {tarea_id}")
        return jsonify({"mensaje": "Tarea eliminada."}), 200

    return app


# Aplicación para ejecución directa: python app.py
app = create_app()

if __name__ == "__main__":
    # debug=False en cualquier entorno que no sea de desarrollo local.
    app.run(host="127.0.0.1", port=5000, debug=False)
