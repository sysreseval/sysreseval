"""``python3 -m sreweb.agent [--config FILE] [--listen HOST:PORT]``: run the agent of a pool host."""
import argparse
import logging
import os
import ssl
import sys

from aiohttp import web

from SRE import params
from .app import Agent
from ..config import load_agent_config, parse_listen, ConfigError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='sre-agent', description="SRE web agent of a pool host")
    parser.add_argument('--config', default=params.agent_config_file, help="configuration file (TOML)")
    parser.add_argument('--listen', default=None, help="host:port to listen on (overrides the file)")
    parser.add_argument('--pub-dir', default=None,
                        help="development only: watch <dir>/projects instead of the projects directory of the "
                             "installation and export SRE_PUB_DIR to sre (the fake sre of tests/mock_sre.py honours it)")
    parser.add_argument('--debug', action='store_true', help="debug logging")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    try:
        cfg = load_agent_config(args.config, sre_exe=params.sre_exe, state_dir=params.sre_pub_dir + '/web-agent')
        if args.listen:
            cfg.listen = parse_listen(args.listen)
    except ConfigError as e:
        print(f"sre-agent: {e}", file=sys.stderr)
        return 1
    ssl_context = None
    if cfg.tls_cert:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    if args.pub_dir:
        pub_dir = os.path.abspath(args.pub_dir)
        os.makedirs(os.path.join(pub_dir, 'projects'), exist_ok=True)
        if not cfg.state_dir or cfg.state_dir.startswith(params.sre_pub_dir):
            cfg.state_dir = os.path.join(pub_dir, 'web-agent')
        agent = Agent(cfg, pub_dir=pub_dir, projects_dir=os.path.join(pub_dir, 'projects'),
                      extra_env={'SRE_PUB_DIR': pub_dir})
    else:
        agent = Agent(cfg)
    host, port = cfg.listen
    logging.getLogger('sreweb.agent').info("listening on %s:%d, sre = %s", host, port, cfg.sre_exe)
    web.run_app(agent.make_app(), host=host, port=port, ssl_context=ssl_context, print=None)
    return 0


if __name__ == '__main__':
    sys.exit(main())
