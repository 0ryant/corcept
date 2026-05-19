.PHONY: fmt clippy test build doctor plugin-zip scaffold-zip eval-local eval-preflight eval-setup eval-external benchmark check contracts validate-audit paired-receipts governance

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace --all-targets

build:
	cargo build --workspace --all-targets

doctor:
	cargo run -p corcept-cli -- doctor --path .

plugin-zip:
	mkdir -p dist
	cd plugins/corcept && zip -r ../../dist/corcept-plugin.zip .

scaffold-zip:
	mkdir -p dist
	zip -r dist/corcept-scaffold.zip . -x 'target/*' 'dist/*' 'evals/corcept-eval-suite-v2/.venv/*' '_compare/*'

eval-setup:
	cd evals/corcept-eval-suite-v2 && ./scripts/setup_env.sh

eval-local: eval-setup
	cd evals/corcept-eval-suite-v2 && make local

eval-preflight: eval-setup
	cd evals/corcept-eval-suite-v2 && make preflight

eval-external: eval-setup
	cd evals/corcept-eval-suite-v2 && ./scripts/setup_external.sh

benchmark:
	python3 benchmarks/run_corcept_benchmark_v2.py --out benchmarks/results

paired-receipts:
	cd evals/corcept-eval-suite-v2 && ./scripts/setup_env.sh
	bash scripts/run_paired_with_receipts.sh

check: fmt clippy test contracts validate-audit

contracts:
	bash scripts/validate-contracts.sh

validate-audit:
	bash scripts/validate-audit-operations.sh

governance:
	bash scripts/supply-chain-gate.sh advisory
