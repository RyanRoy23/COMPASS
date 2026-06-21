.PHONY: build run demo history test shell clean

build:
	docker build -t nis2-risk-analyzer:latest .

run:
	docker compose run --rm nis2-analyzer

demo:
	docker compose run --rm nis2-analyzer --demo

history:
	docker compose run --rm nis2-analyzer --history

test:
	docker compose run --rm --entrypoint python nis2-analyzer -m pytest tests/ -v

shell:
	docker compose run --rm --entrypoint bash nis2-analyzer

clean:
	docker compose down -v
	docker rmi nis2-risk-analyzer:latest 2>/dev/null || true
