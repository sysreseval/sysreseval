"""
Shared fixtures for the SRE test suite.

Run with:
    source venv/bin/activate && python -m pytest tests/ -v
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make src/ and lib/ importable without installing.
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

# Stub out Kathara before any SRE import so tests work without Docker/pkg_resources.
for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
    'Kathara.event', 'Kathara.event.EventDispatcher',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()


@pytest.fixture(autouse=True)
def mock_sre_args():
    """Set a minimal SRE.args so utils helpers that inspect it don't crash."""
    from SRE import params
    mock = MagicMock()
    mock.user = False
    mock.debug = False
    params.SRE.args = mock
    yield mock
    params.SRE.args = None


@pytest.fixture
def tmp_lab_dir(tmp_path, monkeypatch):
    """Patch params.lab_dir to a fresh temp directory."""
    from SRE import params
    lab_dir = tmp_path / 'lab'
    lab_dir.mkdir()
    monkeypatch.setattr(params, 'lab_dir', str(lab_dir))
    return lab_dir


@pytest.fixture
def tmp_pub_dir(tmp_path, monkeypatch):
    """Patch params.sre_pub_dir and related paths to a fresh temp directory."""
    from SRE import params
    pub = tmp_path / 'pub'
    pub.mkdir()
    monkeypatch.setattr(params, 'sre_pub_dir', str(pub))
    monkeypatch.setattr(params, 'sre_projects_dir', str(pub / 'projects'))
    monkeypatch.setattr(params, 'self_grade_timestamp_dir', str(pub / 'last_self_grades'))
    return pub
