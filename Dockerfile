# Dockerfile para EjecutorSSH
FROM python:3.11-slim

# Variables de entorno para evitar prompts de Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar archivos de la aplicación
COPY app.py /app/
COPY templates /app/templates
COPY scripts /app/scripts  # Corrige la ruta de destino aquí

# Instalar dependencias de Python (si las hay)
# Si tienes un requirements.txt, descomenta la siguiente línea:
# COPY requirements.txt /app/
# RUN pip install --no-cache-dir -r requirements.txt

# Instalar Flask
RUN pip install --no-cache-dir flask

# Exponer el puerto por defecto de Flask
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["python", "app.py"]
