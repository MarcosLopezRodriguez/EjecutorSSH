# EjecutorSSH

EjecutorSSH es una aplicación web desarrollada en Flask que permite gestionar, lanzar y detener scripts de túneles SSH de forma sencilla y centralizada. Está pensada para administradores y usuarios que requieren automatizar la apertura de túneles SSH definidos en scripts Bash.

## Características principales
- **Listado automático de scripts**: Busca y muestra todos los scripts `.sh` en el directorio configurado (`BASE_DIR`).
- **Lanzamiento de túneles**: Permite ejecutar scripts en modo normal, con sudo, con sshpass (contraseña SSH), o combinando ambos.
- **Detención de túneles**: Puedes detener túneles individualmente o todos a la vez.
- **Relanzamiento automático**: Si un túnel se cae, el sistema intenta relanzarlo según el modo de ejecución.
- **Detección de túneles externos**: Identifica procesos SSH activos en el sistema que coincidan con los scripts.
- **Descarga y visualización de scripts**: Permite copiar el contenido de los scripts desde la interfaz web.

## Requisitos
- Python 3.x
- Flask
- sshpass (para modo sshpass)
- Acceso a sudo si se requiere ejecutar scripts con privilegios

## Instalación
1. Clona el repositorio o copia los archivos en tu máquina.
2. Instala las dependencias de Python:
   ```bash
   pip install flask
   ```
3. (Opcional) Instala `sshpass` si vas a usar esa funcionalidad:
   ```bash
   sudo apt-get install sshpass
   ```
4. Configura la variable `BASE_DIR` en `app.py` para apuntar al directorio donde están tus scripts `.sh`.

## Uso
1. Ejecuta la aplicación:
   ```bash
   python3 app.py
   ```
2. Accede a la interfaz web en [http://localhost:5000](http://localhost:5000).
3. Desde la interfaz podrás:
   - Ver todos los scripts disponibles
   - Lanzar túneles en diferentes modos
   - Detener túneles
   - Descargar/ver scripts

## Seguridad
- Solo permite copiar scripts ubicados bajo el directorio configurado (`BASE_DIR`).
- La clave secreta de Flask debe cambiarse en producción (`app.secret_key`).
- El uso de sudo y sshpass implica riesgos; asegúrate de proteger el acceso a la aplicación.

## Estructura del proyecto
```
app.py                # Código principal de la aplicación Flask
docker-compose.yml    # (Opcional) Configuración para Docker Compose
Dockerfile            # (Opcional) Dockerfile para contenerización
static/               # Archivos estáticos (JS, CSS)
templates/            # Plantillas HTML (Jinja2)
tunnel_events.log     # Log de eventos de túneles
```

## Docker
Puedes ejecutar la aplicación en un contenedor Docker. Ejemplo básico:
```bash
docker build -t ejecutorssh .
docker run -p 5000:5000 ejecutorssh
```

## Licencia
Este proyecto se distribuye bajo la licencia MIT.

## Autor
Marcos López

---
¡Contribuciones y sugerencias son bienvenidas!
