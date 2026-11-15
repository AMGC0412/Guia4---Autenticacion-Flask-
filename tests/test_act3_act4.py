#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas de las Actividades 3 y 4 y Ejercicios 3.1 / 4.1 (Guía 04).

Cubren:
  • Act. 3  — explotación real de app_vulnerable.py: IDOR, SQLi y XSS
              (demuestran que los hallazgos A, B y C son explotables).
  • Ej. 3.1 — validación de POST /tasks: campo vacío, demasiado largo,
              estado inválido, campo inyectado (role:admin), Unicode,
              sin token; y log de advertencia sin payload.
  • Act. 4  — app_segura.py: 403 por propiedad, parametrización,
              escape de salida.
  • Ej. 4.1 — búsqueda: entradas normales, largas, comillas, especiales,
              nulas; y la versión INSEGURA de referencia falla igual
              que el código "antes" de la guía.
"""

import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app_vulnerable as av
import app_segura as asg


# ---------------------------------------------------------------------------
# Fixtures: base temporal por prueba (aislamiento total)
# ---------------------------------------------------------------------------
@pytest.fixture()
def cliente_vuln():
    with tempfile.TemporaryDirectory() as d:
        av.DB_PATH = os.path.join(d, "vuln.db")
        av.init_db()
        av.app.config["TESTING"] = True
        with av.app.test_client() as c:
            seed_vuln(av.DB_PATH)
            yield c


@pytest.fixture()
def cliente_segura():
    with tempfile.TemporaryDirectory() as d:
        asg.DB_PATH = os.path.join(d, "seg.db")
        asg.init_db()
        asg.app.config["TESTING"] = True
        with asg.app.test_client() as c:
            seed_segura(asg.DB_PATH)
            yield c


def seed_vuln(path):
    import sqlite3
    db = sqlite3.connect(path)
    ts = time.time()
    db.executescript(
        f"""
        INSERT INTO users (id, email, nombre, password_hash, rol, creado_en) VALUES
          (1, 'ana@sport.com',  'Ana',  'x', 'estudiante', {ts}),
          (2, 'luis@sport.com', 'Luis', 'x', 'estudiante', {ts});
        INSERT INTO reservas (id, user_id, cancha, fecha) VALUES
          (104, 1, 'Fútbol 5', '2026-11-20'),
          (105, 2, 'Tennis',   '2026-11-21');
        INSERT INTO comentarios (user_id, contenido, creado_en) VALUES
          (1, 'Gran cancha', {ts}),
          (2, '<script>alert(1)</script>', {ts});
        """
    )
    db.commit()
    db.close()


def seed_segura(path):
    import sqlite3
    import hashlib
    ts = time.time()
    hash_ana = hashlib.sha256(b"tok_ana").hexdigest()
    hash_luis = hashlib.sha256(b"tok_luis").hexdigest()
    db = sqlite3.connect(path)
    db.executescript(
        f"""
        INSERT INTO users (id, email, nombre, password_hash, rol, creado_en) VALUES
          (1, 'ana@sport.com',  'Ana',  'x', 'estudiante', {ts}),
          (2, 'luis@sport.com', 'Luis', 'x', 'estudiante', {ts});
        INSERT INTO sessions (token_hash, user_id, expira_en) VALUES
          ('{hash_ana}',  1, {ts + 3600}),
          ('{hash_luis}', 2, {ts + 3600});
        INSERT INTO reservas (id, user_id, cancha, fecha) VALUES
          (104, 1, 'Fútbol 5', '2026-11-20'),
          (105, 2, 'Tennis',   '2026-11-21');
        INSERT INTO comentarios (user_id, contenido, creado_en) VALUES
          (1, 'Gran cancha', {ts}),
          (2, '<script>alert(1)</script>', {ts});
        INSERT INTO tasks (owner_id, titulo, estado, creado_en) VALUES
          (1, 'Reservar cancha viernes', 'pendiente', {ts}),
          (2, 'Comprar pelotas',         'completada', {ts});
        """
    )
    db.commit()
    db.close()


AUTH_ANA = {"Authorization": "Bearer tok_ana"}


# ===========================================================================
# ACTIVIDAD 3 — demostración de explotación sobre el código VULNERABLE
# ===========================================================================
class TestHallazgoA_IDOR:
    """Hallazgo A: cambiar id=104 por id=105 entrega datos ajenos."""

    def test_idor_reserva_propia(self, cliente_vuln):
        r = cliente_vuln.get("/reservas?id=104")
        assert r.status_code == 200
        assert r.get_json()["user_id"] == 1

    def test_idor_lee_reserva_ajena(self, cliente_vuln):
        """El atacante (sin sesión) ve la reserva privada de otro usuario."""
        r = cliente_vuln.get("/reservas?id=105")
        assert r.status_code == 200          # ← el defecto: NO debió entregarla
        assert r.get_json()["user_id"] == 2  # datos privados de Luis expuestos
        assert r.get_json()["cancha"] == "Tennis"


class TestHallazgoB_SQLi:
    """Hallazgo B: la búsqueda por correo es inyectable."""

    def test_busqueda_normal(self, cliente_vuln):
        r = cliente_vuln.get("/api/buscar?email=ana@sport.com")
        assert r.status_code == 200
        assert len(r.get_json()) == 1

    def test_inyeccion_tautologia_listo_todo(self, cliente_vuln):
        """' OR 1=1 -- extrae la tabla COMPLETA de usuarios."""
        r = cliente_vuln.get("/api/buscar?email=' OR 1=1 --")
        assert r.status_code == 200
        assert len(r.get_json()) >= 2        # fugó todos los usuarios


class TestHallazgoC_XSS:
    """Hallazgo C: la salida no se escapa."""

    def test_xss_almacenado_se_devuelve_sin_escapar(self, cliente_vuln):
        r = cliente_vuln.get("/api/comentarios")
        cuerpos = [c["contenido"] for c in r.get_json()]
        # el payload <script> viaja crudo: el navegador de la víctima lo ejecuta
        assert "<script>alert(1)</script>" in cuerpos


# ===========================================================================
# ACTIVIDAD 4 — correcciones sobre app_segura.py
# ===========================================================================
class TestPaso2_IDOR_corregido:
    def test_reserva_propia_ok(self, cliente_segura):
        r = cliente_segura.get("/reservas?id=104", headers=AUTH_ANA)
        assert r.status_code == 200
        assert r.get_json()["cancha"] == "Fútbol 5"

    def test_reserva_ajena_http_403(self, cliente_segura):
        """Ana pide la reserva 105 (de Luis) → 403 y sin datos."""
        r = cliente_segura.get("/reservas?id=105", headers=AUTH_ANA)
        assert r.status_code == 403
        assert "cancha" not in (r.get_json() or {})

    def test_reserva_ajena_registra_auditoria(self, cliente_segura):
        cliente_segura.get("/reservas?id=105", headers=AUTH_ANA)
        logs = [l for l in _logs(asg) if l["evento"] == "acceso_no_autorizado_reserva"]
        assert logs and "regla=propiedad_recurso" in logs[-1]["detalle"]
        assert "105" not in logs[-1]["detalle"]   # el payload NO se guarda

    def test_sin_sesion_http_401(self, cliente_segura):
        r = cliente_segura.get("/reservas?id=104")
        assert r.status_code == 401

    def test_id_no_numerico_400(self, cliente_segura):
        r = cliente_segura.get("/reservas?id=abc", headers=AUTH_ANA)
        assert r.status_code == 400


class TestPaso1_SQLi_corregido:
    def test_busqueda_parametrizada(self, cliente_segura):
        r = cliente_segura.get("/api/buscar?email=ana@sport.com")
        assert r.status_code == 200
        assert r.get_json()[0]["email"] == "ana@sport.com"

    def test_payload_tautologia_no_inyecta(self, cliente_segura):
        """La misma inyección del hallazgo B ya no altera la consulta."""
        r = cliente_segura.get("/api/buscar?email=' OR 1=1 --")
        assert r.status_code == 400            # rechazada por validación
        assert r.get_json() == {"error": "Parámetro inválido."}


class TestPaso3_XSS_corregido:
    def test_salida_escapada(self, cliente_segura):
        r = cliente_segura.get("/api/comentarios")
        cuerpos = [c["contenido"] for c in r.get_json()]
        # el <script> se devuelve como texto visible, no ejecutable
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in cuerpos
        assert "<script>alert(1)</script>" not in cuerpos


# ===========================================================================
# EJERCICIO 3.1 — validación de POST /tasks
# ===========================================================================
class TestValidacionTasks:
    _SIN_TOKEN = object()  # centinela: distinguir "sin cabeceras" de "default"

    def _post(self, c, body, headers=_SIN_TOKEN):
        return c.post("/tasks", json=body,
                      headers=AUTH_ANA if headers is self._SIN_TOKEN else headers)

    def test_tarea_valida_201(self, cliente_segura):
        r = self._post(cliente_segura, {
            "titulo": "Llevar pelotas",
            "descripcion": "Dos tubos",
            "estado": "pendiente"})
        assert r.status_code == 201

    def test_campo_vacio_400(self, cliente_segura):
        assert self._post(cliente_segura, {"titulo": "  "}).status_code == 400

    def test_titulo_demasiado_largo_400(self, cliente_segura):
        assert self._post(cliente_segura, {"titulo": "x" * 121}).status_code == 400

    def test_titulo_demasiado_corto_400(self, cliente_segura):
        assert self._post(cliente_segura, {"titulo": "ab"}).status_code == 400

    def test_descripcion_demasiado_larga_400(self, cliente_segura):
        r = self._post(cliente_segura, {"titulo": "Válido",
                                        "descripcion": "y" * 1001})
        assert r.status_code == 400

    def test_estado_invalido_400(self, cliente_segura):
        r = self._post(cliente_segura, {"titulo": "Válido",
                                        "estado": "hackeado"})
        assert r.status_code == 400

    def test_campo_inyectado_role_admin_400(self, cliente_segura):
        """Mass assignment: role:"admin" debe rechazarse."""
        r = self._post(cliente_segura, {"titulo": "Válido", "role": "admin"})
        assert r.status_code == 400
        assert r.get_json() == {"error": "Campos no permitidos."}

    def test_unicode_y_espacios_aceptados(self, cliente_segura):
        r = self._post(cliente_segura, {"titulo": "  Tarea ñoño ✔ ", 
                                        "descripcion": "café résumé"})
        assert r.status_code == 201

    def test_sin_token_401(self, cliente_segura):
        assert self._post(cliente_segura, {"titulo": "Válido"},
                          headers=None).status_code == 401

    def test_log_advertencia_sin_payload(self, cliente_segura):
        """El log registra la regla y el parámetro, NO el contenido inyectado."""
        self._post(cliente_segura, {"titulo": "ok", "role": "admin"})
        logs = [l for l in _logs(asg) if l["evento"] == "validacion_fallida"]
        assert logs
        assert "regla=campo_desconocido parametro=role" == logs[-1]["detalle"]


# ===========================================================================
# EJERCICIO 4.1 — búsqueda parametrizada antes/después
# ===========================================================================
class TestBusqueda41:
    def test_entrada_normal(self, cliente_segura):
        r = cliente_segura.get("/api/tasks/buscar?q=cancha", headers=AUTH_ANA)
        assert r.status_code == 200
        assert any("cancha" in t["titulo"] for t in r.get_json())

    def test_comillas_no_rompen(self, cliente_segura):
        r = cliente_segura.get("/api/tasks/buscar?q=\"'`", headers=AUTH_ANA)
        assert r.status_code == 400            # rechazadas por lista blanca

    def test_cadena_larga_400(self, cliente_segura):
        r = cliente_segura.get("/api/tasks/buscar?q=" + "x" * 61,
                               headers=AUTH_ANA)
        assert r.status_code == 400

    def test_valor_nulo(self, cliente_segura):
        """q vacío → lista las tareas propias (LIKE '%%' sobre el dueño)."""
        r = cliente_segura.get("/api/tasks/buscar?q=", headers=AUTH_ANA)
        assert r.status_code == 200
        assert all(t["owner_id"] == 1 for t in r.get_json())

    def test_caracteres_especiales_400(self, cliente_segura):
        r = cliente_segura.get("/api/tasks/buscar?q=%27%20OR%201%3D1%20--",
                               headers=AUTH_ANA)
        assert r.status_code == 400

    def test_version_insegura_referencia(self, cliente_segura):
        """La función ANTES (concatenación) reproduce el defecto: el payload
        modifica la estructura de la consulta. Se evalúa directamente para
        documentar el contraste con la versión parametrizada."""
        with asg.app.test_request_context():
            filas = asg.buscar_tareas_INSEGURA("' OR 1=1 -- ")
            assert len(filas) >= 2             # inyectó: vio tareas ajenas


def _logs(modulo):
    import sqlite3
    db = sqlite3.connect(modulo.DB_PATH)
    db.row_factory = sqlite3.Row
    filas = db.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
    db.close()
    return [dict(f) for f in filas]
