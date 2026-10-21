"""sreweb: the web front-end of SRE.

Two programs share this package:

* ``sreweb.portal`` (``sre-web``): the web site the browsers talk to.  It authenticates the users
  (LDAP, or everyone anonymous), keeps a signed session cookie, knows the pool of hosts and relays
  every request about a project to the agent of the host running it.  It needs neither Docker,
  Kathara nor ``sre`` and imports nothing from ``SRE``.
* ``sreweb.agent`` (``sre-agent``): the daemon of a pool host.  It drives the ``sre`` CLI in user
  mode on behalf of the web users exactly as ``sre-wrapper`` does for the Qt GUI, owns the
  terminals (a pty per ``sre connect``), writes the answers and schedules the evaluations the Qt
  GUI used to run.

``config.py`` and ``identity.py`` are shared by both.
"""
