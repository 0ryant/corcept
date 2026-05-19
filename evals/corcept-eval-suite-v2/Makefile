.PHONY: local preflight pair clean setup setup-external external-smoke

PYTHON := ./scripts/python.sh

local: setup
	$(PYTHON) -m corcept_eval run-local --out results/local

preflight: setup
	$(PYTHON) -m corcept_eval preflight --out results/preflight.json

pair:
	./scripts/run_pair_mini_swe.sh

setup:
	./scripts/setup_env.sh

setup-external:
	./scripts/setup_external.sh

external-smoke:
	./scripts/run_external_smoke.sh

paired-all:
	./scripts/python.sh -m corcept_eval run-paired-all --out ../../results/paired-v1 --repo-root ../.. --plugin-dir ../../plugins/corcept

clean:
	rm -rf results
