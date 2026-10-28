from ..utils import user_not_allowed
from ..wipe import wipe


def action_wipe():
    user_not_allowed()      # privileged only: `sre stop-all` is the user-mode form
    wipe()
