.PHONY: install run quality test eval

install:
	python -m pip install -r requirements-dev.txt

run:
	uvicorn main:app --app-dir backend --reload --port 8000

quality:
	ruff check backend tests scripts
	ruff format --check backend tests scripts
	pytest --cov=backend --cov-report=term-missing
	python scripts/evaluate.py

test:
	pytest

eval:
	python scripts/evaluate.py
