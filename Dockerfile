FROM python:3.12-slim

WORKDIR /app

# Dépendances web d'abord (cache Docker)
COPY requirements-web.txt .
RUN pip install --no-cache-dir -r requirements-web.txt

COPY nis2_analyzer/ ./nis2_analyzer/
COPY serve.py .

RUN useradd --create-home --shell /bin/bash compass && \
    mkdir -p /home/compass/.nis2_analyzer /app/reports && \
    chown -R compass:compass /app /home/compass/.nis2_analyzer
USER compass

# Historique SQLite persistant + rapports HTML générés par le CLI
VOLUME ["/home/compass/.nis2_analyzer", "/app/reports"]
EXPOSE 8000

# Par défaut : interface web. CLI toujours disponible via
#   docker compose run --rm compass python -m nis2_analyzer --demo
CMD ["python", "serve.py"]
