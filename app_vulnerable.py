#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app_vulnerable.py — ACTIVIDAD 3 de la Guía de Práctica 04 (ISW, UNSAAC).

Código defectuoso provisto por el "equipo de desarrollo inicial" de
SportReserve Co. Reproduce los tres hallazgos de la auditoría:

  Hallazgo A (IDOR)          → GET /reservas?id=... entrega la reserva sin
                               verificar propiedad: basta cambiar id=104 por
                               id=105 para ver datos ajenos.
  Hallazgo B (Inyección SQL) → GET /api/buscar?email=... concatena la entrada
                               del usuario directamente en la consulta.
  Hallazgo C (XSS)           → GET /api/comentarios imprime el contenido sin
                               ningún filtro de salida.

ESTE ARCHIVO ES INSEGURO A PROPÓSITO. No corregir aquí: la versión
refactorizada está en app_segura.py (Actividad 4).

Uso:  python app_vulnerable.py   →  http://127.0.0.1:5002
"""

import sqlite3
import time

from flask import Flask, g, jsonify, request

DB_PATH = "guia4_vulnerable.db"

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Base de datos (misma estructura que el resto de la guía)
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
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
        CREATE TABLE IF NOT EXISTS reservas (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            cancha     TEXT NOT NULL,
            fecha      TEXT NOT NULL,
            estado     TEXT NOT NULL DEFAULT 'confirmada'
        );
        CREATE TABLE IF NOT EXISTS comentarios (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            contenido  TEXT NOT NULL,
            creado_en  REAL NOT NULL
        );
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# HALLAZGO A — IDOR: sin verificación de propiedad del recurso
# ---------------------------------------------------------------------------
@app.get("/reservas")
def obtener_reserva():
    """Entrega la reserva que el id indique, de quien sea.

    Vulnerable: el id llega del query string y se usa sin comprobar que la
    reserva pertenezca al usuario de la sesión. Un cliente puede cambiar
    /reservas?id=104 por /reservas?id=105 y ver datos privados ajenos.
    """
    reserva_id = request.args.get("id", "")
    db = get_db()
    # (consulta sobre el id, pero SIN el filtro user_id — el defecto está en la
    #  autorización, no en el SQL de esta línea)
    fila = db.execute(
        "SELECT id, user_id, cancha, fecha, estado FROM reservas WHERE id = "
        + reserva_id
    ).fetchone()
    if fila is None:
        return jsonify({"error": "Reserva no encontrada"}), 404
    return jsonify(dict(fila))


# ---------------------------------------------------------------------------
# HALLAZGO B — Inyección SQL: concatenación de la entrada del usuario
# ---------------------------------------------------------------------------
@app.get("/api/buscar")
def buscar_usuario():
    """Busca usuarios por correo concatenando la entrada en el SQL.

    Vulnerable: email llega del query string y se une con "+" a la consulta.
    Un atacante puede enviar:  ' OR 1=1 --   y manipular la base de datos.
    """
    email = request.args.get("email", "")
    db = get_db()
    consulta = "SELECT id, email, nombre, rol FROM users WHERE email = '" + email + "'"
    filas = db.execute(consulta).fetchall()
    return jsonify([dict(f) for f in filas])


# ---------------------------------------------------------------------------
# HALLAZGO C — XSS: salida sin escape ni filtrado
# ---------------------------------------------------------------------------
@app.get("/api/comentarios")
def listar_comentarios():
    """Devuelve los comentarios tal cual, para que el navegador los imprima.

    Vulnerable: el contenido ingresado por los usuarios se devuelve sin
    escapar; si alguien guardó <script>...</script> como "comentario", se
    ejecuta en el navegador de quien lo ve (XSS almacenado).
    """
    db = get_db()
    filas = db.execute(
        "SELECT id, user_id, contenido, creado_en FROM comentarios ORDER BY id DESC"
    ).fetchall()
    return jsonify([dict(f) for f in filas])


@app.post("/api/comentarios")
def crear_comentario():
    """Guarda el comentario sin validación ni saneamiento."""
    data = request.get_json(force=True, silent=True) or {}
    contenido = data.get("contenido", "")
    db = get_db()
    cur = db.execute(
        "INSERT INTO comentarios (user_id, contenido, creado_en) VALUES (?, ?, ?)",
        (data.get("user_id", 1), contenido, time.time()),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid}), 201


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5002, debug=False)
