.PHONY: install api web test build smoke data train

install:
	python -m pip install -r apps/api/requirements.txt
	cd apps/web && npm ci

api:
	uvicorn app.main:app --app-dir apps/api --reload

web:
	cd apps/web && npm run dev

test:
	python -m pytest apps/api/tests tests -q
	cd apps/web && npm run typecheck

build:
	cd apps/web && npm run build

smoke:
	python scripts/smoke_test.py

data:
	python scripts/download_data.py
	python scripts/validate_data.py
	python scripts/preprocess_data.py

train:
	python scripts/train_model.py
