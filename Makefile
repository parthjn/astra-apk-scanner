.PHONY: install test run ingest providers clean
install:   ## install package + dev deps
	pip install -e ".[dev]"
test:      ## run the offline test suite (no API key)
	pytest -q
ingest:    ## ingest the decompiled app and print stats
	python -m apkscan.cli ingest
run:       ## full teacher->student loop (averaged)
	python -m apkscan.cli run --set eval.repeats=3
providers: ## list registered model providers
	python -m apkscan.cli providers
clean:     ## remove run artifacts and caches
	rm -rf runs/* .pytest_cache; find . -name __pycache__ -type d -prune -exec rm -rf {} +
