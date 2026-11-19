"""The sub-path the portal is served under (``base_path`` of ``web.toml``, ``''`` = the root of
the host name).

One convention: the paths the code names, compares, logs and sends to the browser in JSON are
those of the application (``/projects``, ``/api/...``), the same with or without a sub-path.  The
sub-path is added where a URL is given to the browser to follow (the attributes of the templates,
the ``Location`` of a redirect, the ``Path`` of a cookie; ``base_path.js`` on the browser side),
and taken away here from what aiohttp says of a request: the application is mounted under the
sub-path (``Portal.make_app``), so the path of a request and the pattern of its route carry it."""


def strip_base(path: str, base: str) -> str:
    """The application path of *path* (``/sre/api/x`` → ``/api/x`` under ``/sre``); *path* itself
    without a sub-path, or outside it."""
    if base and (path == base or path.startswith(base + '/')):
        return path[len(base):] or '/'
    return path


def route_pattern(request, base: str) -> str:
    """The pattern of the route of *request* as it was registered (``/api/projects/{host}/{rln}``;
    ``''`` when no route matched): what ``accesslog.EVENTS`` and ``routes.SPECTATOR_ROUTES`` are
    keyed on."""
    canonical = getattr(request.match_info.route.resource, 'canonical', '') or ''
    if base and (canonical == base or canonical.startswith(base + '/')):
        return canonical[len(base):]
    return canonical
