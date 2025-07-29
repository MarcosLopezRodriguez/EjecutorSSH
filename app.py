#!/usr/bin/env python3
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort
import subprocess
import os
import signal
import re
import shlex

app = Flask(__name__)
app.secret_key = "cambia_esta_clave"  # Cambia esto por una clave segura

# Diccionario para almacenar los procesos en ejecución
processes = {}

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
            print(f"[AVISO] El túnel '{os.path.basename(script)}' (PID {proc.pid}) se ha caído o terminado.")
            del processes[script]

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
    return render_template("index.html",
                           scripts=scripts,
                           processes=processes,
                           scripts_info=scripts_info,
                           tuneles_externos=tuneles_externos)


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
        # Creamos un grupo de procesos (preexec_fn=os.setsid)
        proc = subprocess.Popen(["bash", script_path], preexec_fn=os.setsid)
        processes[script_path] = proc
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
        # Inyectamos la contraseña
        proc.stdin.write(sudo_password + "\n")
        proc.stdin.flush()
        processes[script_path] = proc
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
        # sshpass -p [contraseña] bash script.sh
        proc = subprocess.Popen(
            ["sshpass", "-p", ssh_password, "bash", script_path],
            preexec_fn=os.setsid
        )
        processes[script_path] = proc
        flash(f"Lanzado con contraseña SSH: {os.path.basename(script_path)}", "success")
    except Exception as e:
        flash(f"Error al lanzar {os.path.basename(script_path)} con contraseña SSH: {e}", "error")

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
