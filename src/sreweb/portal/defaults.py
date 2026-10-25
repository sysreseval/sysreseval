"""The default paths of ``sre-web`` and ``sre-web-tool``: the configuration file, the templates,
the catalogs and the state file, on a checkout and in the Debian package.  The portal imports no
SRE module (``params.web_config_file`` serves ``sre-agent``), so the checkout defaults are
repeated here."""
import os
from pathlib import Path

FHS_WEB_DIR = '/usr/share/sysreseval/web'
# The configuration file of a checkout (params.web_config_file) and of the Debian package.
CONFIG = '/etc/sreweb/web.toml'
FHS_CONFIG = '/etc/sysreseval/web.toml'
FHS_LOCALE = '/usr/share/locale'
FHS_STATE_DIR = '/var/lib/sre-web'


def root() -> Path:
    return Path(__file__).resolve().parents[3]   # <root>/src/sreweb/portal/defaults.py


def default_web_dir() -> str:
    return FHS_WEB_DIR if os.path.isdir(FHS_WEB_DIR) and not (root() / 'web').is_dir() else str(root() / 'web')


def default_config_file() -> str:
    return CONFIG if os.path.exists(CONFIG) or not os.path.exists(FHS_CONFIG) else FHS_CONFIG


def default_locale_dirs() -> list:
    return [str(root() / 'locale'), FHS_LOCALE]


def default_state_file(config_file: str) -> str:
    if os.path.isdir(FHS_STATE_DIR):
        return os.path.join(FHS_STATE_DIR, 'pool.json')
    return os.path.join(os.path.dirname(os.path.abspath(config_file)), 'pool.json')
