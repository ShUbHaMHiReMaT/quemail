"""Configuration and logging safety."""

from __future__ import annotations

import pytest

from qumail.config import load_config, load_dotenv, load_imap, load_smtp
from qumail.errors import ConfigError
from qumail.logging_setup import redact


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Start every test from an environment with no QuMail settings."""
    import os

    for key in [k for k in os.environ if k.startswith("QUMAIL_")]:
        monkeypatch.delenv(key, raising=False)


class TestFailClosed:
    def test_no_default_credentials_exist(self, monkeypatch):
        """The whole point: nothing ships with an account baked in."""
        monkeypatch.setenv("QUMAIL_SMTP_HOST", "smtp.example.com")
        with pytest.raises(ConfigError, match="QUMAIL_SMTP_USERNAME"):
            load_smtp()

    def test_missing_imap_credentials_are_refused(self, monkeypatch):
        monkeypatch.setenv("QUMAIL_IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("QUMAIL_IMAP_USERNAME", "u@example.com")
        with pytest.raises(ConfigError, match="QUMAIL_IMAP_PASSWORD"):
            load_imap()

    def test_plaintext_smtp_is_not_an_option(self, monkeypatch):
        for key, value in [
            ("QUMAIL_SMTP_HOST", "smtp.example.com"),
            ("QUMAIL_SMTP_USERNAME", "u@example.com"),
            ("QUMAIL_SMTP_PASSWORD", "p"),
            ("QUMAIL_SMTP_SECURITY", "none"),
        ]:
            monkeypatch.setenv(key, value)
        with pytest.raises(ConfigError, match="starttls"):
            load_smtp()

    def test_bad_integer_is_refused(self, monkeypatch):
        monkeypatch.setenv("QUMAIL_POLL_INTERVAL", "soon")
        with pytest.raises(ConfigError, match="must be an integer"):
            load_config()

    def test_out_of_range_integer_is_refused(self, monkeypatch):
        monkeypatch.setenv("QUMAIL_POLL_INTERVAL", "0")
        with pytest.raises(ConfigError, match="between"):
            load_config()

    def test_odd_mailbox_names_are_refused(self, monkeypatch):
        for key, value in [
            ("QUMAIL_IMAP_HOST", "imap.example.com"),
            ("QUMAIL_IMAP_USERNAME", "u@example.com"),
            ("QUMAIL_IMAP_PASSWORD", "p"),
            ("QUMAIL_IMAP_MAILBOX", 'INBOX" (\\Deleted)'),
        ]:
            monkeypatch.setenv(key, value)
        with pytest.raises(ConfigError, match="unsupported characters"):
            load_imap()


class TestDotenv:
    def test_loads_values(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# a comment\n"
            "QUMAIL_SMTP_HOST=smtp.example.com\n"
            "\n"
            'export QUMAIL_SMTP_USERNAME="quoted@example.com"\n'
        )
        load_dotenv(env_file)

        import os

        assert os.environ["QUMAIL_SMTP_HOST"] == "smtp.example.com"
        assert os.environ["QUMAIL_SMTP_USERNAME"] == "quoted@example.com"

    def test_real_environment_wins(self, tmp_path, monkeypatch):
        """A stale file in an image must not override injected secrets."""
        monkeypatch.setenv("QUMAIL_SMTP_HOST", "from-environment")
        env_file = tmp_path / ".env"
        env_file.write_text("QUMAIL_SMTP_HOST=from-file\n")
        load_dotenv(env_file)

        import os

        assert os.environ["QUMAIL_SMTP_HOST"] == "from-environment"

    def test_missing_file_is_fine(self, tmp_path):
        load_dotenv(tmp_path / "absent.env")


class TestRedaction:
    @pytest.mark.parametrize(
        "text",
        [
            "QUMAIL_SMTP_PASSWORD=hunter2hunter2",
            "QUMAIL_KEYSTORE_PASSPHRASE: hunter2hunter2",
            "app_pw = hunter2hunter2",
            "api-key=hunter2hunter2",
        ],
    )
    def test_credentials_never_reach_the_log(self, text):
        assert "hunter2" not in redact(text)
        assert "<redacted>" in redact(text)

    def test_key_material_is_scrubbed(self):
        assert "<redacted>" in redact("key: " + "9f" * 32)

    def test_ordinary_messages_are_left_alone(self):
        message = "polling imap.gmail.com every 30s as bob@example.com"
        assert redact(message) == message
