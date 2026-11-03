.PHONY: install dev test lint run clean

install:            ## user-level install + first-run setup
	./install.sh

dev:                ## editable install with dev tools
	python -m pip install -e ".[dev]"

test:               ## run the test suite
	python -m unittest discover -s tests -v

lint:               ## real-bug lint (needs ruff)
	ruff check .

run:                ## example scan
	npc-fingerprint -u https://example.com

clean:
	rm -rf build dist *.egg-info src/*.egg-info .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
