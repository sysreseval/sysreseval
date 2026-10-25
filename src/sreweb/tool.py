"""``sre-web-tool COMMAND ...``: manage the pool of the running portal from the command line
(``python3 -m sreweb.tool`` from a checkout).  The commands, in ``sreweb.portal.poolctl``:

  sre-web-tool list | status | add | remove | enable | disable | wake | poweroff | drain
"""
import sys

from .portal.defaults import default_config_file
from .portal.poolctl import main as pool_main


def main(argv=None) -> int:
    return pool_main(sys.argv[1:] if argv is None else list(argv), default_config_file())


if __name__ == '__main__':
    sys.exit(main())
