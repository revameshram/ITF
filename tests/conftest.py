import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def app_session(tmp_path_factory):
    from backend.core import AegisApp
    return AegisApp(tmp_path_factory.mktemp("aegis"))


@pytest.fixture
def app(app_session):
    """A clean demo pipeline for every test (reset takes ~0.5 s)."""
    app_session.reset_demo(actor="test")
    return app_session


@pytest.fixture
def store(tmp_path):
    from backend.store import Store
    return Store(tmp_path / "t.db")


@pytest.fixture
def key():
    from backend.crypto.keys import SigningKey
    return SigningKey.generate()
