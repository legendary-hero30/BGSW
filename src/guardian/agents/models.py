"""Provider-independent construction of live language models.

The product path uses a real model only. Deterministic scanners produce the facts; the model
explains them through tool calls, and a deterministic gate validates every claim. There is no
offline/template model in this module.

External calls stay off unless ``GUARDIAN_ALLOW_EXTERNAL_MODELS=1`` is set for the run (D8-02).
DeepInfra is the configured provider. API keys are read by each provider SDK from its usual
environment variable, which is kept outside the workspace and never logged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

ALLOW_ENV = "GUARDIAN_ALLOW_EXTERNAL_MODELS"
# provider -> (init_chat_model provider id, Python package needed)
PROVIDERS = {
    "deepinfra": ("openai", "langchain_openai"),
    "openai": ("openai", "langchain_openai"),
    "openai_compatible": ("openai", "langchain_openai"),  # custom base_url
    "anthropic": ("anthropic", "langchain_anthropic"),
    "google_genai": ("google_genai", "langchain_google_genai"),
    "deepseek": ("deepseek", "langchain_deepseek"),
    "ollama": ("ollama", "langchain_ollama"),
}
# OpenAI-compatible providers with a known default endpoint.
COMPATIBLE_BASE_URLS = {"deepinfra": "https://api.deepinfra.com/v1/openai"}
# Tool-calling models used when --model is omitted. Providers without an entry need --model.
DEFAULT_MODELS = {
    "deepinfra": "deepseek-ai/DeepSeek-V4.1-Flash-1017",
}
DEFAULT_PROVIDER = "deepinfra"


def default_model(provider: str) -> str:
    if provider in DEFAULT_MODELS:
        return DEFAULT_MODELS[provider]
    raise ValueError(f"--model is required for provider {provider!r}")


class ModelDisabledError(RuntimeError):
    pass


@dataclass(frozen=True)
class ModelConfig:
    provider: str = DEFAULT_PROVIDER
    model: str = DEFAULT_MODELS[DEFAULT_PROVIDER]
    base_url: str | None = None  # openai_compatible / ollama only
    temperature: float = 0.0


def build_model(cfg: ModelConfig) -> BaseChatModel:
    if cfg.provider not in PROVIDERS:
        raise ValueError(f"unknown provider {cfg.provider!r}; known: {sorted(PROVIDERS)}")

    if os.environ.get(ALLOW_ENV) != "1":
        raise ModelDisabledError(
            f"external model calls are disabled; set {ALLOW_ENV}=1 after authorizing the "
            f"provider '{cfg.provider}' and the data it will receive (see LLM_PROVIDERS.md)"
        )

    provider_id, package = PROVIDERS[cfg.provider]
    try:
        __import__(package)
    except ImportError as exc:
        raise ModelDisabledError(
            f"provider package {package} is not installed; install the matching extra "
            f"(see LLM_PROVIDERS.md) after approval"
        ) from exc

    from langchain.chat_models import init_chat_model

    kwargs: dict[str, Any] = {"temperature": cfg.temperature}
    base_url = cfg.base_url or COMPATIBLE_BASE_URLS.get(cfg.provider)
    if base_url:
        kwargs["base_url"] = base_url
    if cfg.provider == "deepinfra":
        key = os.environ.get("DEEPINFRA_API_KEY")
        if not key:
            raise ModelDisabledError("DEEPINFRA_API_KEY is not set")
        kwargs["api_key"] = key
    return init_chat_model(cfg.model, model_provider=provider_id, **kwargs)


def provider_key(model: BaseChatModel) -> str | None:
    """The provider name Deep Agents uses to look up harness profiles for this model."""
    try:
        params = model._get_ls_params()
    except Exception:
        return None
    return params.get("ls_provider") if isinstance(params, dict) else None
