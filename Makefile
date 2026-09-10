.PHONY: build up down web demo history shell test clean

# ── Docker : interface web ────────────────────────────────────────────────────
build:            ## Construire l'image
	docker compose build

up:               ## Lancer l'interface web → http://localhost:8000
	docker compose up

down:             ## Arrêter
	docker compose down

# ── Docker : CLI ponctuel ─────────────────────────────────────────────────────
demo:             ## Démonstration CLI
	docker compose run --rm compass python -m nis2_analyzer --demo

history:          ## Historique des assessments
	docker compose run --rm compass python -m nis2_analyzer --history

shell:            ## Shell interactif dans le conteneur
	docker compose run --rm compass bash

# ── Local (venv) ──────────────────────────────────────────────────────────────
web:              ## Interface web sans Docker
	pip install -q -r requirements-web.txt && python serve.py

test:             ## Tests (environnement local, pas l'image runtime)
	python -m pytest tests/ -q

clean:            ## Supprimer conteneurs, volumes et image
	docker compose down -v
	docker rmi compass:latest 2>/dev/null || true
