# LLM providers

Status on 2026-11-23: **DeepInfra is the configured provider and a live run is verified.**
`deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017` explained a real NodeGoat run through the
orchestrator and gate: 10 accepted, 1 rejected attempt, 0 blocked, 13 tool calls. The provider
path, default model and key handling are implemented and locked. Keys live outside the workspace.

## Policy

- **One interface:** all model access goes through
  `guardian.agents.models.build_model(ModelConfig)`. Agents, tools and the gate are
  provider-independent.
- **No offline model:** there is no scripted or template model in the product. The test suite
  injects a test-only fixture into `run_agents(..., model=...)`; production always builds a live
  provider model.
- **External calls are off by default.** A model is built only when both of these hold:
  1. The user has authorized that provider, and the data it will receive (finding facts and
     evidence excerpts, which can include repository text).
  2. `GUARDIAN_ALLOW_EXTERNAL_MODELS=1` is set in the environment of that run.

  Otherwise `build_model` raises `ModelDisabledError` and the CLI exits with code 2.
- **API keys:** keys are read by each provider SDK from its usual environment variable, set
  outside the workspace. Guardian never reads, logs, stores or exports them.
- **No silent fallback:** there is no fallback to a different provider or model when one fails.
- **Capabilities:** a model must support tool calling. Structured output, streaming and pricing
  are not assumed. Explanations come back through a tool call and are validated by the
  deterministic gate, whatever model wrote them.
- **Tracing:** LangSmith tracing is forced off (`LANGSMITH_TRACING=false`) unless the user
  explicitly sets it.

## Providers

| `--provider` | Backed by | Package | Installed | Notes |
|---|---|---|---|---|
| `deepinfra` (default) | OpenAI client, `https://api.deepinfra.com/v1/openai` | `langchain-openai` 1.8.0 | yes, via `--extra llm-openai` | Needs `DEEPINFRA_API_KEY`. Default model `deepseek-ai/DeepSeek-V4.1-Flash-1017` (tool calling) |
| `openai_compatible` | OpenAI client with `--base-url` | `langchain-openai` 1.8.0 | yes, via `--extra llm-openai` | Local OpenAI-compatible servers (e.g. Ollama's `/v1`) |
| `openai` | `init_chat_model(..., model_provider="openai")` | `langchain-openai` 1.8.0 | yes, via `--extra llm-openai` | Needs `OPENAI_API_KEY` |
| `anthropic` | `init_chat_model(..., model_provider="anthropic")` | `langchain-anthropic` 1.7.10 | yes (pulled in by deepagents) | Needs `ANTHROPIC_API_KEY` |
| `google_genai` | `init_chat_model(..., model_provider="google_genai")` | `langchain-google-genai` 4.5.0 | yes (pulled in by deepagents) | Needs a Google API key |
| `deepseek` | `init_chat_model(..., model_provider="deepseek")` | `langchain-deepseek` | no: needs approval | |
| `ollama` | `init_chat_model(..., model_provider="ollama")` | `langchain-ollama` | no: needs approval | Local; still requires the opt-in. The OpenAI-compatible route needs no extra |

The OpenAI-compatible client is declared in `pyproject.toml` as the optional `llm-openai` extra and
is in `uv.lock`, so the DeepInfra path is reproducible with:

```bash
uv sync --locked --extra llm-openai
```

## DeepInfra example

```bash
export DEEPINFRA_API_KEY=...            # set outside the workspace, never committed
export GUARDIAN_ALLOW_EXTERNAL_MODELS=1

uv run --locked python -m guardian.agents analyze --run runs/demo --limit 10 \
  --provider deepinfra
# default model: deepseek-ai/DeepSeek-V4.1-Flash-1017
# override with --model <deepinfra-model-id>
```

If the key cannot be exported into the session environment, keep it in a file outside the
workspace (never inside it) and read it only for the run:

```bash
mkdir -p ~/.config/guardian && chmod 700 ~/.config/guardian
printf '%s' '<key>' > ~/.config/guardian/deepinfra.key && chmod 600 ~/.config/guardian/deepinfra.key
DEEPINFRA_API_KEY="$(cat ~/.config/guardian/deepinfra.key)" \
  GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.agents analyze --run runs/demo --limit 10 \
  --provider deepinfra
```

Guardian never writes that value to logs, the store, run artifacts or reports; the agent trace
records only provider and model names.

One command (baseline already present in `runs/demo`):

```bash
make demo            # reads DEEPINFRA_API_KEY or ~/.config/guardian/deepinfra.key
```

The API and UI use the same configuration. Start them with the key in the process environment so
the GitHub repository box can run the analysis:

```bash
DEEPINFRA_API_KEY="$(cat ~/.config/guardian/deepinfra.key)" \
  GUARDIAN_ALLOW_EXTERNAL_MODELS=1 \
  uv run --locked python -m guardian.api --port 8000
```

Paid calls cost money and send finding data (facts and quoted evidence excerpts) to DeepInfra.
The user selected DeepInfra and is responsible for having authorized that data transfer and for
the model choice. A different model can be selected with `--model` (or `GUARDIAN_MODEL`) without
changing code.
