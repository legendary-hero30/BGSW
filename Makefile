UV ?= uv
RUN ?= runs/demo
LIMIT ?= 20
PORT ?= 8000


.PHONY: remediation-demo help sync ui scan agents deepinfra api demo test lint fmt integration clean

help:
	@printf '%s\n' \
	  'make sync         install the locked Python environment (+ OpenAI-compatible client)' \
	  'make ui           rebuild the React evidence UI into ui/dist' \
	  'make scan         discovery + detection + scoring into $(RUN)' \
	  'make agents       DeepInfra analysis of $(RUN) (needs DEEPINFRA_API_KEY)' \
	  'make deepinfra    alias for make agents' \
	  'make api          serve the read-only API + UI on 127.0.0.1:$(PORT)' \
	  'make demo         scan if needed, explain, then serve (one command)' \
	  'make test         unit and contract tests' \
	  'make integration  real offline scanner integration tests' \
	  'make lint         ruff check + format check' \
	  'make clean        remove pytest caches'

sync:
	$(UV) sync --locked --extra llm-openai

ui:
	cd ui && npm ci && npm run build

scan:
	$(UV) run --locked python -m guardian.scan baseline --target nodegoat --out $(RUN)

agents:
	./scripts/deepinfra_demo.sh "$(RUN)" "$(LIMIT)"

deepinfra: agents

api:
	$(UV) run --locked python -m guardian.api --host 127.0.0.1 --port $(PORT)

demo: ui
	./scripts/demo.sh "$(RUN)"

test:
	$(UV) run --locked pytest -m "not integration"

integration:
	$(UV) run --locked pytest -m integration

lint:
	$(UV) run --locked ruff check .
	$(UV) run --locked ruff format --check .

clean:
	rm -rf .pytest_cache .ruff_cache

remediation-demo:
	./scripts/run_demo.sh $(ARGS)
