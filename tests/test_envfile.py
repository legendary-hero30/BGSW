"""The .env loader: allow-list, precedence, quoting, permissions warning."""

import os

from guardian.envfile import load_env, parse


def test_parse_allows_only_known_keys_and_handles_quotes():
    text = (
        "# comment\nDEEPINFRA_API_KEY='abc123'\nexport GUARDIAN_ALLOW_EXTERNAL_MODELS=1 # on\n"
        'PATH="/evil"\nGUARDIAN_PRICE_IN_PER_M=\nLD_PRELOAD=/x\n'
    )
    assert parse(text) == {"DEEPINFRA_API_KEY": "abc123", "GUARDIAN_ALLOW_EXTERNAL_MODELS": "1"}


def test_environment_wins_and_values_are_not_leaked(tmp_path, monkeypatch, capsys):
    f = tmp_path / ".env"
    f.write_text("DEEPINFRA_API_KEY=from-file\nGUARDIAN_ALLOW_REGISTRY_ACCESS=1\n")
    f.chmod(0o600)
    monkeypatch.setenv("DEEPINFRA_API_KEY", "from-shell")
    monkeypatch.delenv("GUARDIAN_ALLOW_REGISTRY_ACCESS", raising=False)
    assert load_env(f) == ["GUARDIAN_ALLOW_REGISTRY_ACCESS"]
    assert os.environ["DEEPINFRA_API_KEY"] == "from-shell"
    assert "from-file" not in capsys.readouterr().err
    monkeypatch.delenv("GUARDIAN_ALLOW_REGISTRY_ACCESS")


def test_missing_file_is_fine_and_loose_permissions_warn(tmp_path, capsys):
    assert load_env(tmp_path / "nope") == []
    f = tmp_path / ".env"
    f.write_text("GUARDIAN_PRICE_IN_PER_M=1\n")
    f.chmod(0o644)
    load_env(f)
    os.environ.pop("GUARDIAN_PRICE_IN_PER_M", None)
    assert "chmod 600" in capsys.readouterr().err
