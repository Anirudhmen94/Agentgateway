.PHONY: run test eval install

install:
	python3 -m pip install -r requirements.txt

run:
	python3 -m src.app

test:
	python3 -m pytest -q

eval:
	python3 -m src.eval_run
