#!/usr/bin/env python3
"""Servidor de despliegue — sirve la página del prototipo en la raíz (/)
y la API de autenticación bajo /api/... desde el mismo proceso.

Uso local:    gunicorn servidor_despliegue:app --bind 0.0.0.0:8000
En Render:    lo configura el archivo render.yaml (start command).
"""
import os

# web_prototipo ya crea la app (create_app) y registra la ruta "/" con la
# página de login; la API queda disponible en /api/... en el mismo proceso.
from web_prototipo import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
