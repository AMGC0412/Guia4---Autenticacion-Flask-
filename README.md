# Guía de Práctica 04 — Ingeniería de Software Seguro (ISW, UNSAAC)

Caso práctico **SportReserve Co.**: API RESTful de reserva de canchas con
vulnerabilidades simuladas (SQLi, IDOR, XSS), auditada y refactorizada
aplicando el SSDLC (Python 3 / Flask / SQLite / Argon2id).

## Contenido del proyecto

| Archivo | Actividad | Descripción |
|---|---|---|
| `app.py` | Ej. 1.2 | API de autenticación segura (Argon2id, bloqueo progresivo, tokens con TTL) |
| `web_prototipo.py` | Ej. 1.2 | Prototipo web de login (capa visual) |
| `app_vulnerable.py` | Act. 3 | Código defectuoso con los hallazgos A (IDOR), B (SQLi) y C (XSS) |
| `app_segura.py` | Act. 4 + Ej. 3.1 + 4.1 | Refactorización: consultas parametrizadas, 403 por propiedad, escape XSS, validación POST /tasks, búsqueda parametrizada |
| `servidor_despliegue.py` | — | Servidor de despliegue (página + API en un proceso) |
| `tests/test_auth.py` | Ej. 1.2 | 21 pruebas de seguridad de sesión |
| `tests/test_act3_act4.py` | Act. 3/4 + Ej. 3.1/4.1 | 29 pruebas: explotación de hallazgos, validación, 403, escape, búsqueda |
| `evidencia/` | Act. 3 | Captura SAST (Bandit + Pylint) y salidas de texto |
| `render.yaml`, `Procfile` | — | Configuración de despliegue en Render |

## Instalación y ejecución

```bash
pip install -r requirements.txt

python app.py             # API de autenticación   → http://127.0.0.1:5000
python web_prototipo.py   # prototipo web          → http://127.0.0.1:5001
python app_vulnerable.py  # app vulnerable (Act.3) → http://127.0.0.1:5002
python app_segura.py      # app refactorizada      → http://127.0.0.1:5003

pytest -v                 # suite completa: 50 pruebas
bandit app_vulnerable.py  # evidencia SAST (2 × B608, líneas 97 y 117)
bandit app_segura.py      # 0 hallazgos
```

## Endpoints de la API de autenticación (app.py)

| Método | Ruta | Descripción |
|--------|------|--------------|
| POST | /api/auth/register | Registro (lista blanca de campos, política de contraseña) |
| POST | /api/auth/login | Login → token Bearer nuevo (TTL 15 min) |
| POST | /api/auth/logout | Revoca la sesión actual |
| GET | /api/me | Perfil del usuario autenticado |
| POST | /api/auth/password/change | Cambio de contraseña → revoca TODAS las sesiones |
| POST | /api/auth/forgot | Solicita token de reset (respuesta genérica) |
| POST | /api/auth/reset | Restablece contraseña con token de un solo uso |
| GET | /api/tasks | Lista SOLO las tareas del dueño |
| POST | /api/tasks | Crea tarea (validación de esquema en servidor) |
| PATCH | /api/tasks/{id} | Edita tarea propia; ajena → **HTTP 403** (anti-IDOR) |
| DELETE | /api/tasks/{id} | Elimina tarea propia; ajena → **HTTP 403** |

## Controles de seguridad implementados

1. **Argon2id** para contraseñas (nunca MD5/SHA-1/SHA-256).
2. **Bloqueo progresivo** por cuenta y por IP: 5 fallos → 30 s, luego 60 s, 120 s… tope 15 min (`HTTP 429`).
3. **Mensajes genéricos**: no se revela si un correo existe (login y forgot).
4. **Tokens de sesión** de 256 bits, hasheados en BD, con expiración de 15 min.
5. **Regeneración del identificador de sesión** en cada login (anti fijación de sesión).
6. **Revocación total de sesiones** al cambiar o restablecer la contraseña.
7. **Token de reset de un solo uso**, expira en 15 min, invalida los anteriores y
   se audita **sin exponer el token** (buzón simulado `app.email_outbox`).
8. **Auditoría** de eventos (`login_ok`, `login_fallido`, `cuenta_o_ip_bloqueada`,
   `reset_solicitado`, `acceso_denegado_idor`, …) sin datos sensibles.
9. **Consultas SQL 100 % parametrizadas** (mitigación de inyección SQL).
10. **Autorización por propiedad** en tareas y reservas: `owner_id`/`user_id`
    se compara en el servidor (mitigación IDOR, `HTTP 403`).
11. **Lista blanca de campos** de entrada: se rechazan campos inyectados como `role=admin`.
12. **Cabeceras de seguridad**: `X-Content-Type-Options`, `X-Frame-Options`, CSP, `no-store`.
13. **Validación de servidor** en POST /tasks (título 3–120, descripción ≤1000,
    estados enumerados, límite 16 KiB) — Ej. 3.1.
14. **Escape contextual de salida** con `markupsafe.escape()` (mitigación XSS) — Act. 4.

## Resumen de resultados

- **Matriz PxI**: IDOR R=20 (crítico), SQLi R=12 y XSS R=12 (alto).
- **SAST (Bandit)**: 2 hallazgos B608 en `app_vulnerable.py` (líneas 97 y 117);
  `app_segura.py` sale limpia.
- **Pruebas automatizadas**: 50/50 aprobadas (21 autenticación + 29 actividades 3–4).
- **Requisitos**: RE-01..RE-04 (Act. 2), RF-01..RF-10 y RS-01..RS-12 con
  matriz de trazabilidad (Ej. 2.1).

## Entrega

- Repositorio: `https://github.com/tu-usuario/Guia4_Autenticacion_Flask`
- Dominio: `https://guia4-autenticacion.onrender.com`
- Bitácora: `Guia Práctica 04 Desarrollada.docx` (subir y compartir el link).

Antes de entregar: reemplazar `tu-usuario` por el usuario real de GitHub y
el enlace del dominio por el que asigne Render, y completar Estudiante y
Equipo en la portada del documento.
