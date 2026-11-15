# -*- coding: utf-8 -*-
"""
GUÍA DE PRÁCTICA 04 – Ejercicio Propuesto 1.2 (paso 5)
Pruebas de seguridad de sesión y autenticación.

Ejecutar:  pytest -v
"""
from __future__ import annotations

import re
import sqlite3
import time

import pytest

from app import create_app, lockout_seconds

PASS_VALIDA = "Clave$egura2026"      # cumple la política (10+, mayús, mínús, dígito, símbolo)
PASS_NUEVA = "0traClave#Segura"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def app(tmp_path):
    aplicacion = create_app(db_path=str(tmp_path / "test.db"))
    aplicacion.config["TESTING"] = True
    return aplicacion


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def usuario(client):
    """Usuario de prueba ya registrado."""
    r = client.post("/api/auth/register", json={
        "email": "ana@unsaac.edu.pe", "password": PASS_VALIDA, "nombre": "Ana"})
    assert r.status_code == 201
    return "ana@unsaac.edu.pe"


def _login(client, email, password, ip=None):
    headers = {"X-Forwarded-For": ip} if ip else {}
    return client.post("/api/auth/login", json={"email": email, "password": password},
                       headers=headers)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _token_de_buzon(app, email="ana@unsaac.edu.pe"):
    """Extrae el token de reset del buzón simulado (nunca llega por HTTP)."""
    for correo in reversed(app.email_outbox):
        if correo["para"] == email:
            m = re.search(r"token=([A-Za-z0-9_\-]+)", correo["enlace"])
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# 1. Registro, login y almacenamiento del hash
# ---------------------------------------------------------------------------
class TestRegistroYLogin:

    def test_registro_login_y_perfil(self, client, usuario):
        r = _login(client, usuario, PASS_VALIDA)
        assert r.status_code == 200
        token = r.get_json()["token"]
        me = client.get("/api/me", headers=_auth(token))
        assert me.status_code == 200
        assert me.get_json()["rol"] == "estudiante"   # rol definido SOLO en servidor

    def test_hash_argon2id_no_texto_plano(self, app, client, usuario):
        db = sqlite3.connect(app.config["DB_PATH"])
        fila = db.execute("SELECT password_hash FROM users WHERE email = ?",
                          (usuario,)).fetchone()
        db.close()
        assert not fila[0].startswith(PASS_VALIDA[:4])
        assert fila[0].startswith("$argon2id$")        # Argon2id, nunca MD5/SHA-1
        assert PASS_VALIDA not in fila[0]              # no hay texto plano

    def test_politica_de_contrasena_rechaza_debiles(self, client):
        for debil in ["abc", "password123", "ABCDEFGHIJ1", "SinSimbolo123"]:
            r = client.post("/api/auth/register", json={
                "email": "x@y.com", "password": debil, "nombre": "X"})
            assert r.status_code == 400, debil

    def test_campo_desconocido_role_admin_rechazado(self, client):
        r = client.post("/api/auth/register", json={
            "email": "malo@y.com", "password": PASS_VALIDA,
            "nombre": "M", "role": "admin"})
        assert r.status_code == 400
        db_r = client.post("/api/auth/register", json={
            "email": "bueno@y.com", "password": PASS_VALIDA, "nombre": "B"})
        assert db_r.status_code == 201


# ---------------------------------------------------------------------------
# 2. Credenciales inválidas y mensajes genéricos
# ---------------------------------------------------------------------------
class TestCredencialesInvalidas:

    def test_mensaje_generico_no_revela_si_el_correo_existe(self, client, usuario):
        r_pass_mala = _login(client, usuario, "Incorrecta#1234")
        r_usuario_inexistente = _login(client, "nadie@unsaac.edu.pe", "Incorrecta#1234")
        assert r_pass_mala.status_code == 401
        assert r_usuario_inexistente.status_code == 401
        # Ambas respuestas son IDÉNTICAS → no hay enumeración de usuarios.
        assert r_pass_mala.get_json() == r_usuario_inexistente.get_json()

    def test_forgot_no_enumera_usuarios(self, client, usuario):
        r_existe = client.post("/api/auth/forgot", json={"email": usuario})
        r_no_existe = client.post("/api/auth/forgot", json={"email": "zzz@unsaac.edu.pe"})
        assert r_existe.status_code == r_no_existe.status_code == 200
        assert r_existe.get_json() == r_no_existe.get_json()


# ---------------------------------------------------------------------------
# 3. Fuerza bruta simulada: límite por cuenta y por IP + bloqueo progresivo
# ---------------------------------------------------------------------------
class TestFuerzaBruta:

    def test_bloqueo_tras_5_intentos_por_cuenta(self, client, usuario):
        for _ in range(5):
            _login(client, usuario, "Mala#Clave99")
        # El 6.º intento se bloquea AUNQUE las credenciales sean correctas.
        r = _login(client, usuario, PASS_VALIDA, ip="203.0.113.10")
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_bloqueo_por_cuenta_aplica_desde_otra_ip(self, client, usuario):
        for _ in range(5):
            _login(client, usuario, "Mala#Clave99", ip="198.51.100.1")
        r = _login(client, usuario, PASS_VALIDA, ip="198.51.100.2")   # IP distinta
        assert r.status_code == 429          # regla por CUENTA (email, '*')

    def test_bloqueo_por_ip_afecta_a_otra_cuenta(self, client, usuario):
        client.post("/api/auth/register", json={
            "email": "bruno@unsaac.edu.pe", "password": PASS_VALIDA, "nombre": "Bruno"})
        for _ in range(5):                    # fallos sobre la cuenta de Ana...
            _login(client, usuario, "Mala#Clave99", ip="192.0.2.9")
        r = _login(client, "bruno@unsaac.edu.pe", PASS_VALIDA, ip="192.0.2.9")
        assert r.status_code == 429          # ...bloquea la IP completa ('*', ip)

    def test_escala_progresiva_30_60_120_y_tope_900(self):
        assert lockout_seconds(4) == 0        # aún sin bloqueo
        assert lockout_seconds(5) == 30       # 1.er bloqueo: 30 s
        assert lockout_seconds(6) == 60       # 2.º: 60 s
        assert lockout_seconds(7) == 120      # 3.º: 120 s
        assert lockout_seconds(20) == 900     # tope: 15 min

    def test_el_bloqueo_expira_y_permite_login(self, app, client, usuario):
        for _ in range(5):
            _login(client, usuario, "Mala#Clave99")
        assert _login(client, usuario, PASS_VALIDA).status_code == 429
        # Se simula el paso del tiempo moviendo la marca de bloqueo en la BD.
        db = sqlite3.connect(app.config["DB_PATH"])
        db.execute("UPDATE login_attempts SET bloqueada_hasta = 0")
        db.commit()
        db.close()
        assert _login(client, usuario, PASS_VALIDA).status_code == 200


# ---------------------------------------------------------------------------
# 4. Tokens de sesión: expiración, revocación y regeneración
# ---------------------------------------------------------------------------
class TestSesiones:

    def test_acceso_con_sesion_expirada(self, tmp_path):
        aplicacion = create_app(db_path=str(tmp_path / "ttl.db"), session_ttl=1)
        aplicacion.config["TESTING"] = True
        c = aplicacion.test_client()
        c.post("/api/auth/register", json={
            "email": "carla@unsaac.edu.pe", "password": PASS_VALIDA, "nombre": "Carla"})
        token = c.post("/api/auth/login", json={
            "email": "carla@unsaac.edu.pe", "password": PASS_VALIDA}).get_json()["token"]
        time.sleep(1.2)                        # deja vencer el TTL de 1 segundo
        r = c.get("/api/me", headers=_auth(token))
        assert r.status_code == 401
        assert r.get_json()["error"] == "Sesión inválida o expirada."

    def test_logout_revoca_el_token(self, client, usuario):
        token = _login(client, usuario, PASS_VALIDA).get_json()["token"]
        assert client.post("/api/auth/logout", headers=_auth(token)).status_code == 200
        assert client.get("/api/me", headers=_auth(token)).status_code == 401

    def test_cada_login_regenera_el_identificador_de_sesion(self, client, usuario):
        t1 = _login(client, usuario, PASS_VALIDA).get_json()["token"]
        t2 = _login(client, usuario, PASS_VALIDA).get_json()["token"]
        assert t1 != t2                          # nunca se reutiliza el identificador

    def test_cambio_de_contrasena_revoca_todas_las_sesiones(self, client, usuario):
        t1 = _login(client, usuario, PASS_VALIDA).get_json()["token"]
        t2 = _login(client, usuario, PASS_VALIDA).get_json()["token"]
        r = client.post("/api/auth/password/change",
                        headers=_auth(t1),
                        json={"password_actual": PASS_VALIDA,
                              "password_nueva": PASS_NUEVA})
        assert r.status_code == 200
        assert client.get("/api/me", headers=_auth(t1)).status_code == 401
        assert client.get("/api/me", headers=_auth(t2)).status_code == 401
        # Y el login requiere la contraseña nueva.
        assert _login(client, usuario, PASS_VALIDA).status_code == 401
        assert _login(client, usuario, PASS_NUEVA).status_code == 200


# ---------------------------------------------------------------------------
# 5. Restablecimiento: token de un solo uso, expiración e invalidación
# ---------------------------------------------------------------------------
class TestRestablecimiento:

    def test_token_de_un_solo_uso(self, app, client, usuario):
        client.post("/api/auth/forgot", json={"email": usuario})
        token = _token_de_buzon(app)
        r1 = client.post("/api/auth/reset",
                         json={"token": token, "password": PASS_NUEVA})
        assert r1.status_code == 200
        r2 = client.post("/api/auth/reset",
                         json={"token": token, "password": "Tercera#Clave99"})
        assert r2.status_code == 400            # reutilización → rechazado

    def test_token_anterior_queda_invalidado(self, app, client, usuario):
        client.post("/api/auth/forgot", json={"email": usuario})
        token_viejo = _token_de_buzon(app)
        client.post("/api/auth/forgot", json={"email": usuario})   # nuevo pedido
        token_nuevo = _token_de_buzon(app)
        assert token_viejo != token_nuevo
        r_viejo = client.post("/api/auth/reset",
                              json={"token": token_viejo, "password": PASS_NUEVA})
        assert r_viejo.status_code == 400       # el anterior fue invalidado
        r_nuevo = client.post("/api/auth/reset",
                              json={"token": token_nuevo, "password": PASS_NUEVA})
        assert r_nuevo.status_code == 200

    def test_token_expirado_rechazado(self, app, client, usuario):
        client.post("/api/auth/forgot", json={"email": usuario})
        token = _token_de_buzon(app)
        db = sqlite3.connect(app.config["DB_PATH"])
        db.execute("UPDATE password_resets SET expira_en = 1")   # simula el paso del tiempo
        db.commit(); db.close()
        r = client.post("/api/auth/reset",
                        json={"token": token, "password": PASS_NUEVA})
        assert r.status_code == 400

    def test_reset_revoca_sesiones_y_audita_sin_token(self, app, client, usuario):
        _login(client, usuario, PASS_VALIDA)
        client.post("/api/auth/forgot", json={"email": usuario})
        token = _token_de_buzon(app)
        client.post("/api/auth/reset", json={"token": token, "password": PASS_NUEVA})
        # El token NUNCA aparece en la auditoría.
        db = sqlite3.connect(app.config["DB_PATH"])
        db.row_factory = sqlite3.Row
        eventos = db.execute("SELECT evento, detalle FROM audit_logs").fetchall()
        activas = db.execute("SELECT COUNT(*) c FROM sessions WHERE revocada = 0").fetchone()
        db.close()
        assert activas["c"] == 0
        for _ev, detalle in eventos:
            assert token not in detalle


# ---------------------------------------------------------------------------
# 6. Autorización por propiedad de recursos (IDOR → HTTP 403)
# ---------------------------------------------------------------------------
class TestIDOR:

    def _crear_usuario_y_tarea(self, client, email):
        client.post("/api/auth/register", json={
            "email": email, "password": PASS_VALIDA, "nombre": email.split("@")[0]})
        token = _login(client, email, PASS_VALIDA).get_json()["token"]
        tarea = client.post("/api/tasks", headers=_auth(token),
                            json={"titulo": "Estudiar SSDLC"})
        return token, tarea.get_json()["id"]

    def test_usuario_b_no_edita_tarea_de_usuario_a(self, client, usuario):
        token_a, tarea_id = self._crear_usuario_y_tarea(client, usuario)
        client.post("/api/auth/register", json={
            "email": "beto@unsaac.edu.pe", "password": PASS_VALIDA, "nombre": "Beto"})
        token_b = _login(client, "beto@unsaac.edu.pe", PASS_VALIDA).get_json()["token"]

        r_edit = client.patch(f"/api/tasks/{tarea_id}", headers=_auth(token_b),
                              json={"estado": "completada"})
        r_del = client.delete(f"/api/tasks/{tarea_id}", headers=_auth(token_b))
        assert r_edit.status_code == 403        # HTTP 403 Forbidden (IDOR bloqueado)
        assert r_del.status_code == 403

        # El dueño sí puede operar su recurso.
        r_ok = client.patch(f"/api/tasks/{tarea_id}", headers=_auth(token_a),
                            json={"estado": "completada"})
        assert r_ok.status_code == 200

    def test_listado_solo_devuelve_tareas_propias(self, client, usuario):
        self._crear_usuario_y_tarea(client, usuario)
        self._crear_usuario_y_tarea(client, "otro@unsaac.edu.pe")
        token = _login(client, usuario, PASS_VALIDA).get_json()["token"]
        tareas = client.get("/api/tasks", headers=_auth(token)).get_json()
        assert len(tareas) == 1                 # nunca tareas ajenas
