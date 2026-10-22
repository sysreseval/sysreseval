"""``python3 -m sreweb.portal [--config FILE] [--listen HOST:PORT]``: run the web site."""
import argparse
import logging
import os
import ssl
import sys
from pathlib import Path

from aiohttp import web

from .app import Portal
from ..config import load_web_config, parse_listen, ConfigError

FHS_WEB_DIR = '/usr/share/sysreseval/web'
FHS_CONFIG = '/etc/sysreseval/web.toml'
FHS_LOCALE = '/usr/share/locale'


def _root() -> Path:
    return Path(__file__).resolve().parents[3]   # <root>/src/sreweb/portal/__main__.py


def default_web_dir() -> str:
    return FHS_WEB_DIR if os.path.isdir(FHS_WEB_DIR) and not (_root() / 'web').is_dir() else str(_root() / 'web')


def default_config_file() -> str:
    checkout = _root() / 'etc' / 'web.toml'
    return str(checkout) if checkout.exists() or not os.path.exists(FHS_CONFIG) else FHS_CONFIG


def default_locale_dirs() -> list:
    return [str(_root() / 'locale'), FHS_LOCALE]


FHS_STATE_DIR = '/var/lib/sre-web'


def default_state_file(config_file: str) -> str:
    if os.path.isdir(FHS_STATE_DIR):
        return os.path.join(FHS_STATE_DIR, 'pool.json')
    return os.path.join(os.path.dirname(os.path.abspath(config_file)), 'pool.json')


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ['pool']:
        from .poolctl import main as pool_main
        return pool_main(argv[1:], default_config_file())
    parser = argparse.ArgumentParser(prog='sre-web', description="SRE web site (sre-web pool ...: manage the pool)")
    parser.add_argument('--config', default=default_config_file(), help="configuration file (TOML)")
    parser.add_argument('--listen', default=None, help="host:port to listen on (overrides the file)")
    parser.add_argument('--web-dir', default=default_web_dir(), help="templates and static files")
    parser.add_argument('--debug', action='store_true', help="debug logging")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    try:
        cfg = load_web_config(args.config)
        if args.listen:
            cfg.listen = parse_listen(args.listen)
        if not cfg.admin.state_file:
            cfg.admin.state_file = default_state_file(args.config)
    except ConfigError as e:
        print(f"sre-web: {e}", file=sys.stderr)
        return 1
    ssl_context = None
    if cfg.tls_cert:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    portal = Portal(cfg, web_dir=args.web_dir, localedirs=default_locale_dirs())
    host, port = cfg.listen
    logging.getLogger('sreweb.portal').info("listening on %s:%d, %d host(s), auth %s", host, port, len(cfg.hosts),
                                            cfg.auth.mode)
    web.run_app(portal.make_app(), host=host, port=port, ssl_context=ssl_context, print=None)
    return 0


if __name__ == '__main__':
    sys.exit(main())
