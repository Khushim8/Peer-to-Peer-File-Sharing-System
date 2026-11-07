import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

TRACKER_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "p2p", "Tracker_server")
sys.path.insert(0, os.path.abspath(TRACKER_DIR))


@pytest.fixture()
def tracker():
    """Tracker app backed by in-memory SQLite.

    app.py hardcodes a MySQL URI at import time, so the engine Flask-SQLAlchemy
    built for it is swapped out here. Creating that engine does not connect,
    so no MySQL server is needed.
    """
    from app import app, db

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    app.config["TESTING"] = True
    db._app_engines[app][None] = engine
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()
