.PHONY: install dev serve init-db check test eval harness prune docker
install:
	python -m pip install -e '.[dev]'
init-db:
	python -m agentgate.cli init-db
dev:
	AGENTGATE_ENV=development AGENTGATE_PUBLIC_DEMO=false AGENTGATE_DEV_MODE=true python -m agentgate.cli init-db
	AGENTGATE_ENV=development AGENTGATE_PUBLIC_DEMO=false AGENTGATE_DEV_MODE=true python -m uvicorn agentgate.api.app:app --host 127.0.0.1 --port 7860 --reload
serve:
	python -m agentgate.cli init-db
	python -m uvicorn agentgate.api.app:app --host 127.0.0.1 --port 7860 --workers 1
check:
	python -m ruff check .
	python -m ruff format --check .
	python -m mypy agentgate
test:
	python -m pytest
eval:
	python -m evals.run --dataset evals/cases.jsonl --mode both --output evals/reports/latest.json
harness:
	python -m agentgate.harness.runner --task refund-approval --mode compare --seed 42 --report evals/reports/comparison.json
prune:
	python -m agentgate.cli prune
docker:
	docker compose up --build

.PHONY: lint format demo docker-up docker-down
lint:
	python -m ruff check .
format:
	python -m ruff format .
demo:
	python -m demo.support_agent.agent --scenario high-value-refund
docker-up:
	docker compose up --build -d
docker-down:
	docker compose down
