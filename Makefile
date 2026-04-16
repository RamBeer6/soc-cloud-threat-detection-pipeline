PYTHON ?= python

.PHONY: install test generate analyze run dashboard clean

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m unittest discover -s tests -v

generate:
	$(PYTHON) src/main.py generate --count 200 --output logs/events.jsonl --seed 42

analyze:
	$(PYTHON) src/main.py analyze --input logs/events.jsonl --alerts-output logs/alerts.log

run:
	$(PYTHON) src/main.py run --count 200 --output logs/events.jsonl --alerts-output logs/alerts.log --seed 42

dashboard:
	$(PYTHON) src/main.py dashboard --input logs/events.jsonl --alerts-output logs/alerts.log

clean:
	-$(PYTHON) -c "from pathlib import Path; [path.unlink() for path in Path('logs').glob('*.log') if path.exists()]; [path.unlink() for path in Path('logs').glob('*.jsonl') if path.exists()]"
