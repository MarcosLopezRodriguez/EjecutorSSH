#!/usr/bin/env python3
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort, jsonify
import subprocess
import os
import signal
import re
import shlex
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = "cambia_esta_clave"  # Cambia esto por una clave segura

# Diccionario para almacenar los procesos en ejecución
processes = {}
# Nuevo: Diccionario para almacenar info de relanzamiento
processes_info = {}
# Nuevo: Set para favoritos (persistente en archivo)
FAVORITOS_FILE = "favoritos.json"
def cargar_favoritos():
    if os.path.exists(FAVORITOS_FILE):
        try:
            with open(FAVORITOS_FILE, "r") as f:
                return set(json.load(f))
        except json.JSONDecodeError:
            print(f"Error: El archivo {FAVORITOS_FILE} contiene datos JSON no válidos.")
            return set()
        except OSError as e:
            print(f"Error de E/S al leer {FAVORITOS_FILE}: {e}")
            return set()
    return set()
def guardar_favoritos(favs):
    try:
        with open(FAVORITOS_FILE, "w") as f:
            json.dump(list(favs), f)
    except Exception as e:
        print(f"Error guardando favoritos: {e}")
favoritos = cargar_favoritos()

# Directorio base donde se buscarán los ficheros .sh
BASE_DIR = os.path.abspath("/home/marcos.lopez/Documentos/TUNELES SSH")

def buscar_scripts(base_dir):
    """
    Busca recursivamente archivos .sh en el directorio base y subdirectorios.
    Retorna una lista con las rutas completas.
    """
    scripts = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".sh"):
                full_path = os.path.join(root, file)
                scripts.append(full_path)
    return scripts

def parse_script_info(script_path):
    """
    Lee el contenido del .sh y extrae (de la primera coincidencia) el dominio/IP,
    el puerto de entrada y el puerto de salida asumiendo un patrón:
      ssh -N -L <port_in>:<domain_or_ip>:<port_out>
    Devuelve (domain, port_in, port_out).
    Si no se encuentra nada, devuelve valores por defecto.
    """
    domain = "Desconocido"
    port_in = "N/A"
    port_out = "N/A"

    # Expresión regular para capturar:
    # ssh (algo) -L <puerto_local>:<dominio/ip>:<puerto_remoto>
    pattern = re.compile(r'ssh\s.*-L\s+(\d+):([^:]+):(\d+)')

    try:
        with open(script_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    port_in = match.group(1)
                    domain = match.group(2)
                    port_out = match.group(3)
                    break  # Tomamos solo la primera coincidencia
    except Exception as e:
        print(f"Error leyendo {script_path}: {e}")
    return domain, port_in, port_out

@app.template_filter("basename")
def basename_filter(path):
    return os.path.basename(path)

# Función para actualizar el diccionario de procesos
def update_processes():
    # Itera sobre una copia de las claves para evitar errores al eliminar
    for script in list(processes.keys()):
        proc = processes[script]
        # Si poll() devuelve algo distinto de None, el proceso ha terminado
        if proc.poll() is not None:
            log_msg = f"[AVISO] El túnel '{os.path.basename(script)}' (PID {proc.pid}) se ha caído o terminado."
            print(log_msg)
            with open("tunnel_events.log", "a") as logf:
                logf.write(f"{log_msg}\n")
            # Intentar relanzar automáticamente si hay info
            info = processes_info.get(script)
            if info:
                print(f"Intentando relanzar automáticamente: {os.path.basename(script)} (modo: {info['mode']})")
                try:
                    if info['mode'] == 'normal':
                        new_proc = subprocess.Popen(["bash", script], preexec_fn=os.setsid)
                    elif info['mode'] == 'sudo':
                        new_proc = subprocess.Popen(
                            ["sudo", "-S", "bash", script],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            preexec_fn=os.setsid
                        )
                        new_proc.stdin.write(info['sudo_password'] + "\n")
                        new_proc.stdin.flush()
                    elif info['mode'] == 'sshpass':
                        new_proc = subprocess.Popen(
                            ["sshpass", "-p", info['ssh_password'], "bash", script],
                            preexec_fn=os.setsid
                        )
                    elif info['mode'] == 'sudo_sshpass':
                        new_proc = subprocess.Popen(
                            ["sudo", "-S", "sshpass", "-p", info['ssh_password'], "bash", script],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            preexec_fn=os.setsid
                        )
                        new_proc.stdin.write(info['sudo_password'] + "\n")
                        new_proc.stdin.flush()
                    else:
                        print(f"Modo de relanzamiento desconocido para {script}")
                        del processes[script]
                        processes_info.pop(script, None)
                        continue
                    processes[script] = new_proc
                    print(f"Túnel relanzado automáticamente: {os.path.basename(script)} (PID {new_proc.pid})")
                    continue  # No borrar info si relanzado
                except Exception as e:
                    print(f"Error relanzando {os.path.basename(script)}: {e}")
            # Si no se pudo relanzar, limpiar
            del processes[script]
            processes_info.pop(script, None)

def extraer_parametros_tunel(script_path):
    """
    Devuelve un dict con los parámetros clave del túnel SSH del script:
    { 'port_in': ..., 'domain': ..., 'port_out': ..., 'user': ..., 'host': ... }
    """
    port_in = domain = port_out = user = host = None
    pattern = re.compile(r'ssh\s+(\S+@)?([\w\.-]+)?\s+-[nN]?T?\s*-L\s*(\d+):([^:]+):(\d+)')
    try:
        with open(script_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    user_host = match.group(1)
                    host = match.group(2)
                    port_in = match.group(3)
                    domain = match.group(4)
                    port_out = match.group(5)
                    if user_host:
                        user = user_host.rstrip('@')
                    break
    except Exception as e:
        print(f"Error extrayendo parámetros de {script_path}: {e}")
    return {'port_in': port_in, 'domain': domain, 'port_out': port_out, 'user': user, 'host': host}

def detectar_tuneles_externos(scripts):
    """
    Busca procesos ssh -N -L ... activos en el sistema y los compara con los parámetros de los scripts.
    Devuelve un dict {script_path: {pid, cmdline}} para los que coincidan.
    """
    externos = {}
    try:
        result = subprocess.run(['ps', 'axo', 'pid,command'], capture_output=True, text=True)
        procesos = [line for line in result.stdout.splitlines() if 'ssh' in line and '-L' in line]
        for script in scripts:
            params = extraer_parametros_tunel(script)
            if not params['port_in'] or not params['domain'] or not params['port_out']:
                continue
            for proc in procesos:
                pid, *cmd = proc.strip().split(maxsplit=1)
                cmdline = cmd[0] if cmd else ''
                # Comprobar si los parámetros clave están en el comando
                if (
                    f"-L {params['port_in']}:{params['domain']}:{params['port_out']}" in cmdline
                    and (not params['host'] or params['host'] in cmdline)
                ):
                    externos[script] = {'pid': int(pid), 'cmdline': cmdline}
    except Exception as e:
        print(f"Error detectando túneles externos: {e}")
    return externos


def build_status_snapshot(scripts, externos=None):
    """Genera un resumen serializable del estado de los tuneles."""
    snapshot = {
        "activos": [],
        "externos": [],
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    for script_path, proc in processes.items():
        snapshot["activos"].append({
            "script": script_path,
            "name": os.path.basename(script_path),
            "pid": proc.pid,
            "mode": processes_info.get(script_path, {}).get("mode")
        })
    snapshot["activos"].sort(key=lambda item: item["name"].lower())

    if externos is None:
        externos = detectar_tuneles_externos(scripts)
    for script_path, info in externos.items():
        snapshot["externos"].append({
            "script": script_path,
            "name": os.path.basename(script_path),
            "pid": info.get("pid"),
            "cmdline": info.get("cmdline", "")
        })
    snapshot["externos"].sort(key=lambda item: item["name"].lower())
    return snapshot

@app.route("/")
def index():
    # Actualizamos el diccionario de procesos: eliminamos los que ya han terminado
    update_processes()

    # Buscamos todos los scripts
    scripts = buscar_scripts(BASE_DIR)
    # Ordenamos por nombre de fichero
    scripts = sorted(scripts, key=lambda s: os.path.basename(s).lower())

    # Extraemos la información (dominio, puertos) de cada script
    scripts_info = {}
    for script_path in scripts:
        domain, port_in, port_out = parse_script_info(script_path)
        scripts_info[script_path] = {
            "domain": domain,
            "port_in": port_in,
            "port_out": port_out
        }
    tuneles_externos = detectar_tuneles_externos(scripts)
    status_snapshot = build_status_snapshot(scripts, tuneles_externos)
    favoritos_actual = cargar_favoritos()
    favoritos_scripts = [s for s in scripts if s in favoritos_actual]
    otros_scripts = [s for s in scripts if s not in favoritos_actual]
    return render_template("index.html",
                           scripts=scripts,
                           processes=processes,
                           scripts_info=scripts_info,
                           status_snapshot=status_snapshot,
                           favoritos=favoritos_actual,
                           favoritos_scripts=favoritos_scripts,
                           otros_scripts=otros_scripts)

@app.route("/api/status")
def api_status():
    update_processes()
    scripts = buscar_scripts(BASE_DIR)
    snapshot = build_status_snapshot(scripts)
    return jsonify(snapshot)


@app.route("/marcar_favorito", methods=["POST"])
def marcar_favorito():
    script = request.form.get("script")
    if not script or not os.path.isfile(script):
        return jsonify({"ok": False}), 400
    favoritos.add(script)
    guardar_favoritos(favoritos)
    return jsonify({"ok": True})

@app.route("/desmarcar_favorito", methods=["POST"])
def desmarcar_favorito():
    script = request.form.get("script")
    if not script or not os.path.isfile(script):
        return jsonify({"ok": False}), 400
    favoritos.discard(script)
    guardar_favoritos(favoritos)
    return jsonify({"ok": True})

@app.route("/launch", methods=["POST"])
def launch():
    script_path = request.form.get("script")
    if not script_path or not os.path.isfile(script_path):
        flash("Script no encontrado", "error")
        return redirect(url_for("index"))
    if script_path in processes:
        flash("El script ya está en ejecución", "info")
        return redirect(url_for("index"))
    try:
        proc = subprocess.Popen(["bash", script_path], preexec_fn=os.setsid)
        processes[script_path] = proc
        processes_info[script_path] = {'mode': 'normal'}
        flash(f"Lanzado: {os.path.basename(script_path)}", "success")
    except Exception as e:
        flash(f"Error al lanzar {script_path}: {e}", "error")
    return redirect(url_for("index"))

@app.route("/launch_sudo", methods=["POST"])
def launch_sudo():
    """
    Lanza el script como sudo, pidiendo la contraseña en el navegador.
    """
    script_path = request.form.get("script")
    sudo_password = request.form.get("password", "")
    if not script_path or not os.path.isfile(script_path):
        flash("Script no encontrado", "error")
        return redirect(url_for("index"))
    if script_path in processes:
        flash("El script ya está en ejecución", "info")
        return redirect(url_for("index"))

    try:
        proc = subprocess.Popen(
            ["sudo", "-S", "bash", script_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid
        )
        proc.stdin.write(sudo_password + "\n")
        proc.stdin.flush()
        processes[script_path] = proc
        processes_info[script_path] = {'mode': 'sudo', 'sudo_password': sudo_password}
        flash(f"Lanzado como sudo: {os.path.basename(script_path)}", "success")
    except Exception as e:
        flash(f"Error al lanzar {os.path.basename(script_path)} como sudo: {e}", "error")

    return redirect(url_for("index"))

@app.route("/launch_sshpass", methods=["POST"])
def launch_sshpass():
    """
    Lanza el script usando sshpass, inyectando la contraseña SSH que el usuario introduce.
    Sirve para scripts que piden password de SSH.
    """
    script_path = request.form.get("script")
    ssh_password = request.form.get("password", "")
    if not script_path or not os.path.isfile(script_path):
        flash("Script no encontrado", "error")
        return redirect(url_for("index"))
    if script_path in processes:
        flash("El script ya está en ejecución", "info")
        return redirect(url_for("index"))

    try:
        proc = subprocess.Popen(
            ["sshpass", "-p", ssh_password, "bash", script_path],
            preexec_fn=os.setsid
        )
        processes[script_path] = proc
        processes_info[script_path] = {'mode': 'sshpass', 'ssh_password': ssh_password}
        flash(f"Lanzado con contraseña SSH: {os.path.basename(script_path)}", "success")
    except Exception as e:
        flash(f"Error al lanzar {os.path.basename(script_path)} con contraseña SSH: {e}", "error")

    return redirect(url_for("index"))

@app.route("/launch_sudo_sshpass", methods=["POST"])
def launch_sudo_sshpass():
    """
    Lanza el script usando sudo y sshpass, inyectando ambas contraseñas.
    """
    script_path = request.form.get("script")
    sudo_password = request.form.get("sudo_password", "")
    ssh_password = request.form.get("ssh_password", "")
    if not script_path or not os.path.isfile(script_path):
        flash("Script no encontrado", "error")
        return redirect(url_for("index"))
    if script_path in processes:
        flash("El script ya está en ejecución", "info")
        return redirect(url_for("index"))

    try:
        proc = subprocess.Popen(
            ["sudo", "-S", "sshpass", "-p", ssh_password, "bash", script_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid
        )
        proc.stdin.write(sudo_password + "\n")
        proc.stdin.flush()
        processes[script_path] = proc
        processes_info[script_path] = {'mode': 'sudo_sshpass', 'sudo_password': sudo_password, 'ssh_password': ssh_password}
        flash(f"Lanzado como sudo + contraseña SSH: {os.path.basename(script_path)}", "success")
    except Exception as e:
        flash(f"Error al lanzar {os.path.basename(script_path)} con sudo y contraseña SSH: {e}", "error")

    return redirect(url_for("index"))

@app.route("/stop", methods=["POST"])
def stop():
    script_path = request.form.get("script")
    if script_path in processes:
        proc = processes[script_path]
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                proc.wait()
            del processes[script_path]
            processes_info.pop(script_path, None)
            flash(f"Detenido: {os.path.basename(script_path)}", "success")
        except Exception as e:
            flash(f"Error al detener {os.path.basename(script_path)}: {e}", "error")
    else:
        flash("El script no se encuentra en ejecución", "error")
    return redirect(url_for("index"))

@app.route("/stop_all", methods=["POST"])
def stop_all():
    if not processes:
        flash("No hay túneles en ejecución", "info")
        return redirect(url_for("index"))
    errors = []
    for script, proc in list(processes.items()):
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                proc.wait()
            del processes[script]
            processes_info.pop(script, None)
        except Exception as e:
            errors.append(f"{os.path.basename(script)}: {e}")
    if errors:
        flash("Algunos túneles no se pudieron detener: " + ", ".join(errors), "error")
    else:
        flash("Todos los túneles han sido detenidos", "success")
    return redirect(url_for("index"))

@app.route("/copiar_script")
def copiar_script():
    script_path = request.args.get("path")
    if not script_path or not os.path.isfile(script_path):
        abort(404)
    # Seguridad: solo permite rutas bajo BASE_DIR
    abs_path = os.path.abspath(script_path)
    if not abs_path.startswith(BASE_DIR):
        abort(403)
    return send_file(abs_path, as_attachment=False, mimetype="text/plain")

if __name__ == "__main__":
    # Si deseas abrir el navegador automáticamente:
    """
    import threading
    import time
    import webbrowser

    def open_browser():
        time.sleep(1)
        webbrowser.open("http://127.0.0.1:5000")

    threading.Thread(target=open_browser).start()
    """
    app.run(debug=True, host="0.0.0.0", port=5000)
