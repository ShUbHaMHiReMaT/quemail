"""Shared fixtures."""

from __future__ import annotations

import pytest

from qumail.config import Config, Policy
from qumail.contacts import ContactStore
from qumail.crypto.keys import PrivateIdentity, generate_identity

PASSPHRASE = "correct-horse-battery-staple"


@pytest.fixture
def alice() -> PrivateIdentity:
    return generate_identity("alice@example.com")


@pytest.fixture
def bob() -> PrivateIdentity:
    return generate_identity("bob@example.com")


@pytest.fixture
def mallory() -> PrivateIdentity:
    return generate_identity("mallory@example.com")


@pytest.fixture
def config(tmp_path) -> Config:
    """A fully local configuration: no SMTP or IMAP credentials needed."""
    return Config(
        home=tmp_path,
        keystore_path=tmp_path / "keystore.json",
        contacts_path=tmp_path / "contacts.json",
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "inbox",
        policy=Policy(),
    )


@pytest.fixture
def contacts(config) -> ContactStore:
    return ContactStore(config.contacts_path)
