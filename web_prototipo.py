#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prototipo web de login — Ejercicio propuesto 1.2 (Guía de Práctica 04).

Sirve una página única de presentación (inicio de sesión, registro y panel
de tareas) que consume la API segura definida en app.py. No modifica la
API: es únicamente la capa visual del prototipo.

Uso:
    python web_prototipo.py        →  http://127.0.0.1:5001
"""
from flask import Response

from app import create_app

HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SportReserve Co. — Iniciar sesión</title>
<style>
  :root { --verde:#0e7a5f; --verde-osc:#0a5c48; --crema:#f6f9f7; --tinta:#1d2b26; }
  * { box-sizing:border-box; margin:0; padding:0; font-family:'Segoe UI', Arial, sans-serif; }
  body { background:linear-gradient(135deg,#0e7a5f 0%,#0a5c48 55%,#073d30 100%); min-height:100vh;
         display:flex; align-items:center; justify-content:center; padding:28px; }
  .tarjeta { background:#ffffff; width:100%; max-width:430px; border-radius:14px;
             box-shadow:0 18px 45px rgba(4,26,20,.45); overflow:hidden; }
  .cab { background:var(--crema); padding:22px 28px; border-bottom:3px solid var(--verde); }
  .cab .logo { display:flex; align-items:center; gap:10px; }
  .cab .balon { width:34px; height:34px; border-radius:50%; background:var(--verde);
                color:#fff; display:flex; align-items:center; justify-content:center;
                font-size:17px; font-weight:700; }
  .cab h1 { font-size:19px; color:var(--tinta); }
  .cab p { font-size:12.5px; color:#5b6f67; margin-top:3px; }
  .cuerpo { padding:26px 28px 30px; }
  .campo { margin-bottom:15px; }
  label { display:block; font-size:12.5px; font-weight:600; color:var(--tinta); margin-bottom:5px; }
  input, select { width:100%; padding:10px 12px; border:1.5px solid #cfdcd6; border-radius:8px;
                  font-size:14px; color:var(--tinta); background:#fbfdfc; }
  input:focus, select:focus { outline:none; border-color:var(--verde); background:#fff; }
  .btn { width:100%; padding:12px; background:var(--verde); color:#fff; border:none;
         border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; }
  .btn:hover { background:var(--verde-osc); }
  .btn-sec { background:none; color:var(--verde); border:none; font-size:13px;
             cursor:pointer; margin-top:14px; font-weight:600; }
  .btn-sec:hover { text-decoration:underline; }
  .aviso { padding:11px 13px; border-radius:8px; font-size:13.5px; margin-bottom:15px; display:none; }
  .error  { background:#fdecea; color:#b3261e; border:1px solid #f5c6c2; }
  .ok     { background:#e8f5ee; color:#0a5c48; border:1px solid #bfe3d0; }
  .pie { text-align:center; font-size:11.5px; color:#8aa096; padding:0 28px 20px; }
  /* Panel de tareas */
  .usuario-bar { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; }
  .usuario-bar .who { font-size:14.5px; color:var(--tinta); }
  .usuario-bar .who b { color:var(--verde-osc); }
  .btn-salir { background:none; border:1.5px solid #cfdcd6; border-radius:7px; padding:7px 13px;
               font-size:12.5px; color:#5b6f67; cursor:pointer; }
  table { width:100%; border-collapse:collapse; margin-top:14px; }
  th { text-align:left; font-size:11.5px; color:#5b6f67; text-transform:uppercase;
       letter-spacing:.4px; padding:8px 8px; border-bottom:2px solid #e3ece7; }
  td { padding:10px 8px; font-size:13.5px; color:var(--tinta); border-bottom:1px solid #eef4f1; }
  .estado { padding:3px 9px; border-radius:20px; font-size:11px; font-weight:600; white-space:nowrap; }
  .pendiente { background:#fdf3d7; color:#8a6100; }
  .en_progreso { background:#ddeafB; color:#1a4f7a; }
  .completada { background:#e2f3e8; color:#0a5c48; }
  h2 { font-size:15px; color:var(--tinta); }
  .nueva { margin-top:20px; background:var(--crema); border:1px solid #e3ece7;
           border-radius:10px; padding:16px; }
</style>
</head>
<body>
  <div class="tarjeta">
    <div class="cab">
      <div class="logo"><div class="balon">S</div>
        <div><h1>SportReserve Co.</h1><p>Reserva de canchas deportivas · acceso a la plataforma</p></div>
      </div>
    </div>
    <div class="cuerpo" id="zona-login">
      <div class="aviso" id="aviso1"></div>
      <div class="campo"><label for="correo">Correo electrónico</label>
        <input id="correo" type="email" placeholder="usuario@unsaac.edu.pe" autocomplete="off"></div>
      <div class="campo"><label for="clave">Contraseña</label>
        <input id="clave" type="password" placeholder="••••••••••••" autocomplete="off"></div>
      <button class="btn" id="btn-login">Iniciar sesión</button>
      <button class="btn-sec" id="btn-ir-registro">¿No tiene cuenta? Registrarse</button>
    </div>

    <div class="cuerpo" id="zona-registro" style="display:none">
      <div class="aviso" id="aviso2"></div>
      <div class="campo"><label for="rnombre">Nombre completo</label>
        <input id="rnombre" type="text" placeholder="Ana Quispe" autocomplete="off"></div>
      <div class="campo"><label for="rcorreo">Correo electrónico</label>
        <input id="rcorreo" type="email" placeholder="ana@unsaac.edu.pe" autocomplete="off"></div>
      <div class="campo"><label for="rclave">Contraseña (mín. 10 caracteres, con mayúscula, minúscula, dígito y símbolo)</label>
        <input id="rclave" type="password" placeholder="••••••••••••" autocomplete="off"></div>
      <button class="btn" id="btn-registro">Crear cuenta</button>
      <button class="btn-sec" id="btn-ir-login">Ya tengo cuenta: iniciar sesión</button>
    </div>

    <div class="cuerpo" id="zona-tareas" style="display:none">
      <div class="usuario-bar">
        <div class="who">Sesión iniciada como <b id="who">—</b></div>
        <button class="btn-salir" id="btn-logout">Cerrar sesión</button>
      </div>
      <h2>Mis tareas</h2>
      <table><thead><tr><th>Título</th><th>Descripción</th><th>Estado</th></tr></thead>
             <tbody id="tbody"></tbody></table>
      <div class="nueva">
        <div class="campo"><label for="titulo">Nueva tarea</label>
          <input id="titulo" type="text" placeholder="Reservar cancha de fulbito — viernes"></div>
        <div class="campo"><label for="estado">Estado</label>
          <select id="estado"><option value="pendiente">Pendiente</option>
            <option value="en_progreso">En progreso</option><option value="completada">Completada</option></select></div>
        <button class="btn" id="btn-tarea">Agregar tarea</button>
      </div>
    </div>
    <div class="pie">Prototipo académico — Guía de Práctica 04 · Ingeniería de Software Seguro (UNSAAC)</div>
  </div>

<script>
  let TOKEN = null, NOMBRE = "";
  const $ = id => document.getElementById(id);
  const mostrar = (el, tipo, texto) => { el.className = "aviso " + tipo; el.textContent = texto; el.style.display = "block"; };
  const ocultar = el => el.style.display = "none";

  async function api(ruta, cuerpo, conToken) {
    const cab = { "Content-Type": "application/json" };
    if (conToken && TOKEN) cab["Authorization"] = "Bearer " + TOKEN;
    const r = await fetch(ruta, { method: "POST", headers: cab, body: JSON.stringify(cuerpo) });
    return { status: r.status, datos: await r.json().catch(() => ({})) };
  }

  $("btn-login").onclick = async () => {
    ocultar($("aviso1"));
    const { status, datos } = await api("/api/auth/login",
      { email: $("correo").value.trim(), password: $("clave").value });
    if (status === 200) {
      TOKEN = datos.token;
      $("zona-login").style.display = "none"; $("zona-tareas").style.display = "block";
      await cargarTareas();
    } else {
      mostrar($("aviso1"), "error", datos.error || "No se pudo iniciar sesión.");
    }
  };

  $("btn-ir-registro").onclick = () => { $("zona-login").style.display = "none"; $("zona-registro").style.display = "block"; };
  $("btn-ir-login").onclick = () => { $("zona-registro").style.display = "none"; $("zona-login").style.display = "block"; };

  $("btn-registro").onclick = async () => {
    ocultar($("aviso2"));
    const { status, datos } = await api("/api/auth/register",
      { nombre: $("rnombre").value.trim(), email: $("rcorreo").value.trim(), password: $("rclave").value });
    if (status === 201) {
      mostrar($("aviso2"), "ok", "Cuenta creada correctamente. Ahora inicie sesión.");
    } else {
      mostrar($("aviso2"), "error", datos.error || "No se pudo completar el registro.");
    }
  };

  async function cargarTareas() {
    const r = await fetch("/api/tasks", { headers: { "Authorization": "Bearer " + TOKEN } });
    if (r.status !== 200) { alert("Sesión expirada"); location.reload(); return; }
    const me = await (await fetch("/api/me", { headers: { "Authorization": "Bearer " + TOKEN } })).json();
    NOMBRE = me.nombre || "usuario";
    $("who").textContent = NOMBRE;
    const tareas = await r.json();
    $("tbody").innerHTML = tareas.map(t =>
      `<tr><td>${t.titulo}</td><td>${t.descripcion || "—"}</td>
       <td><span class="estado ${t.estado}">${t.estado.replace("_", " ")}</span></td></tr>`).join("")
      || '<tr><td colspan="3">Sin tareas registradas.</td></tr>';
  }

  $("btn-tarea").onclick = async () => {
    const { status, datos } = await api("/api/tasks",
      { titulo: $("titulo").value.trim(), descripcion: "", estado: $("estado").value }, true);
    if (status === 201) { $("titulo").value = ""; await cargarTareas(); }
    else alert(datos.error || "No se pudo crear la tarea.");
  };

  $("btn-logout").onclick = async () => {
    await api("/api/auth/logout", {}, true);
    TOKEN = null; location.reload();
  };
</script>
</body>
</html>"""

app = create_app()

@app.get("/")
def prototipo():
    """Página única del prototipo (solo presentación; la seguridad vive en la API).

    La API responde con Content-Security-Policy: default-src 'none' (véase el
    control RS-08). Esta página declara una CSP propia que permite únicamente
    sus estilos y scripts inline y las llamadas fetch a la propia API: el
    after_request de la API usa setdefault, por lo que no la sobreescribe.
    """
    resp = Response(HTML, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
