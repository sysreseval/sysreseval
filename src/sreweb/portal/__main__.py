"""``python3 -m sreweb.portal [--config FILE] [--listen HOST:PORT]``: run the web site.  The pool
of the running portal is managed with ``sre-web-tool ...`` (``sreweb.tool``)."""
import argparse
import logging
import ssl
import sys

from aiohttp import web

from .app import Portal
from .defaults import default_web_dir, default_config_file, default_locale_dirs, default_state_file
from ..config import load_web_config, parse_listen, ConfigError, AUTH_PROXY

MOVED_TO_TOOL = ('pool',)     # the former `sre-web pool ...`


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] and argv[0] in MOVED_TO_TOOL:
        print(f"sre-web: `sre-web {argv[0]} ...` is now `sre-web-tool ...`", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(prog='sre-web', description="SRE web site (the pool: sre-web-tool ...)")
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
        portal = Portal(cfg, web_dir=args.web_dir, localedirs=default_locale_dirs())
        app = portal.make_app()          # opens the connection log file: a ConfigError when it cannot
    except ConfigError as e:
        print(f"sre-web: {e}", file=sys.stderr)
        return 1
    ssl_context = None
    if cfg.tls_cert:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    host, port = cfg.listen
    logger = logging.getLogger('sreweb.portal')
    logger.info("listening on %s:%d, %d host(s), auth %s", host, port, len(cfg.hosts), cfg.auth.mode)
    if cfg.auth.mode == AUTH_PROXY:
        logger.info("identity headers trusted from %s", ', '.join(str(n) for n in cfg.trusted_proxies))
    logger.info("connection log: %s", portal.access.describe())
    web.run_app(app, host=host, port=port, ssl_context=ssl_context, print=None)
    return 0


if __name__ == '__main__':
    sys.exit(main())
