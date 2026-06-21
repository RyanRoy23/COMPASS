FROM python:3.11-slim

WORKDIR /app

COPY nis2_analyzer/ ./nis2_analyzer/
COPY tests/ ./tests/

RUN pip install --no-cache-dir pytest pytest-cov

RUN useradd --create-home --shell /bin/bash nis2user && \
    mkdir -p /home/nis2user/.nis2_analyzer && \
    chown -R nis2user:nis2user /app /home/nis2user/.nis2_analyzer

USER nis2user

VOLUME ["/home/nis2user/.nis2_analyzer", "/app/reports"]

ENTRYPOINT ["python", "-m", "nis2_analyzer"]
CMD ["--help"]
