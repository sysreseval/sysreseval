"""A REST northbound API for OpenFlow 1.3 switches (OS-Ken application).

OS-Ken 3 (the OpenStack fork of Ryu packaged by Debian 13) no longer ships Ryu's
``ofctl_rest`` nor its WSGI framework.  This application gives back the part of that API the
labs use, with the same URLs and JSON documents (the conversions are those of
``os_ken.lib.ofctl_v1_3``, the code Ryu's ofctl_rest used), so that Ryu's documentation applies:

    osken-manager os_ken.app.ofctl_rest            (listens on 0.0.0.0:8080)

The address and port come from the environment: ``OFCTL_REST_HOST``, ``OFCTL_REST_PORT``.

A datapath ID in a URL or in a ``"dpid"`` field is a decimal integer (``161``), as in Ryu; a
string written ``0x...`` is read in hexadecimal (``"0xa1"``).

    GET    /stats/switches                       the connected switches: [dpid, ...]
    GET    /stats/desc/<dpid>                    the description of a switch
    GET    /stats/portdesc/<dpid>                its ports (number, name, MAC, state)
    GET    /stats/port/<dpid>[/<port>]           the counters of its ports
    GET    /stats/flow/<dpid>                    its flow entries (POST: with a filter document)
    GET    /stats/meterconfig/<dpid>             its meters
    GET    /stats/meter/<dpid>                   the counters of its meters
    GET    /stats/groupdesc/<dpid>               its groups
    POST   /stats/flowentry/add                  add a flow entry
    POST   /stats/flowentry/modify               modify the actions of the matching entries
    POST   /stats/flowentry/modify_strict        ... of the entry with exactly this match / priority
    POST   /stats/flowentry/delete               delete the matching entries
    POST   /stats/flowentry/delete_strict        delete the entry with exactly this match / priority
    DELETE /stats/flowentry/clear/<dpid>         delete every entry of every table
    POST   /stats/meterentry/add|modify|delete   meters
    POST   /stats/groupentry/add|modify|delete   groups
    GET    /stats/errors/<dpid>                  (not in Ryu) the last OpenFlow errors the switch
                                                 sent back: a flow refused by the switch is only
                                                 known there, the POST itself has succeeded

Example::

    curl -X POST -d '{"dpid": 161, "priority": 100,
                      "match": {"in_port": 2, "eth_type": 2048, "ipv4_dst": "10.0.0.2"},
                      "actions": [{"type": "OUTPUT", "port": 3}]}' \\
         http://controller:8080/stats/flowentry/add
"""

import json
import logging
import os
import re
import time
from collections import deque

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub, ofctl_v1_3
from os_ken.ofproto import ofproto_v1_3

LOG = logging.getLogger("os_ken.app.ofctl_rest")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
ERRORS_KEPT = 20

_STATUS = {200: "200 OK", 400: "400 Bad Request", 404: "404 Not Found", 405: "405 Method Not Allowed",
           500: "500 Internal Server Error"}

# the replies the stats requests of ofctl_v1_3 wait for
_REPLY_EVENTS = [
    ofp_event.EventOFPStatsReply,
    ofp_event.EventOFPDescStatsReply,
    ofp_event.EventOFPFlowStatsReply,
    ofp_event.EventOFPPortStatsReply,
    ofp_event.EventOFPPortDescStatsReply,
    ofp_event.EventOFPMeterStatsReply,
    ofp_event.EventOFPMeterConfigStatsReply,
    ofp_event.EventOFPGroupDescStatsReply,
]


class RestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def parse_dpid(value) -> int:
    """A datapath ID given by the user: an int, a decimal string or a ``0x`` string."""
    if isinstance(value, bool):
        raise RestError(400, f"invalid datapath id: {value!r}")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        raise RestError(400, f"invalid datapath id: {value!r} (a decimal integer, or a string 0x...)")


class RestStatsApi(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}  # dpid -> datapath
        self.waiters = {}  # dpid -> {xid: (event, msgs)}, filled by ofctl_v1_3
        self.errors = {}  # dpid -> deque of the last error messages
        host = os.environ.get("OFCTL_REST_HOST", DEFAULT_HOST)
        port = int(os.environ.get("OFCTL_REST_PORT", DEFAULT_PORT))
        self.server = hub.WSGIServer((host, port), self.wsgi_app)
        LOG.info("REST API listening on %s:%s", host, port)

    def start(self):
        super().start()
        self.threads.append(hub.spawn(self.server.serve_forever))

    # -- OpenFlow side -------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if dp.id is None:
            return
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            LOG.info("switch %016x (%d) connected", dp.id, dp.id)
        elif self.datapaths.get(dp.id) is dp:
            del self.datapaths[dp.id]
            LOG.info("switch %016x (%d) disconnected", dp.id, dp.id)

    @set_ev_cls(_REPLY_EVENTS, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        waiters = self.waiters.get(dp.id, {})
        if msg.xid not in waiters:
            return
        lock, msgs = waiters[msg.xid]
        msgs.append(msg)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return
        del waiters[msg.xid]
        lock.set()

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        entry = {"time": time.strftime("%H:%M:%S"), "type": msg.type, "code": msg.code,
                 "description": self._error_text(dp, msg.type, msg.code)}
        self.errors.setdefault(dp.id, deque(maxlen=ERRORS_KEPT)).append(entry)
        LOG.warning("switch %016x refused a message: %s", dp.id, entry["description"])

    @staticmethod
    def _error_text(dp, err_type, code) -> str:
        ofp = dp.ofproto
        type_name = next((n for n in dir(ofp) if n.startswith("OFPET_") and getattr(ofp, n) == err_type),
                         str(err_type))
        prefixes = {"OFPET_BAD_MATCH": "OFPBMC_", "OFPET_BAD_ACTION": "OFPBAC_", "OFPET_BAD_INSTRUCTION": "OFPBIC_",
                    "OFPET_FLOW_MOD_FAILED": "OFPFMFC_", "OFPET_METER_MOD_FAILED": "OFPMMFC_",
                    "OFPET_GROUP_MOD_FAILED": "OFPGMFC_", "OFPET_BAD_REQUEST": "OFPBRC_"}
        prefix = prefixes.get(type_name)
        code_name = str(code)
        if prefix:
            code_name = next((n for n in dir(ofp) if n.startswith(prefix) and getattr(ofp, n) == code), code_name)
        return f"{type_name} / {code_name}"

    # -- REST side -----------------------------------------------------------------------------

    def _dp(self, dpid_text):
        dpid = parse_dpid(dpid_text)
        dp = self.datapaths.get(dpid)
        if dp is None:
            raise RestError(404, f"no connected switch with datapath id {dpid} (0x{dpid:x})")
        return dp

    def _body(self, environ) -> dict:
        try:
            size = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            size = 0
        raw = environ["wsgi.input"].read(size) if size else b""
        if not raw.strip():
            return {}
        try:
            body = json.loads(raw)
        except ValueError as e:
            raise RestError(400, f"the body is not a JSON document: {e}")
        if not isinstance(body, dict):
            raise RestError(400, "the body must be a JSON object")
        return body

    def _dp_of_body(self, body: dict):
        if "dpid" not in body:
            raise RestError(400, 'the body needs a "dpid" field')
        return self._dp(body["dpid"])

    def _flowentry(self, cmd_name: str, body: dict):
        dp = self._dp_of_body(body)
        ofp = dp.ofproto
        commands = {"add": ofp.OFPFC_ADD, "modify": ofp.OFPFC_MODIFY, "modify_strict": ofp.OFPFC_MODIFY_STRICT,
                    "delete": ofp.OFPFC_DELETE, "delete_strict": ofp.OFPFC_DELETE_STRICT}
        if cmd_name not in commands:
            raise RestError(404, f"unknown command {cmd_name}")
        ofctl_v1_3.mod_flow_entry(dp, body, commands[cmd_name])
        LOG.info("flowentry/%s on %016x: %s", cmd_name, dp.id, json.dumps(body, sort_keys=True))
        return None

    def _meterentry(self, cmd_name: str, body: dict):
        dp = self._dp_of_body(body)
        ofp = dp.ofproto
        commands = {"add": ofp.OFPMC_ADD, "modify": ofp.OFPMC_MODIFY, "delete": ofp.OFPMC_DELETE}
        if cmd_name not in commands:
            raise RestError(404, f"unknown command {cmd_name}")
        ofctl_v1_3.mod_meter_entry(dp, body, commands[cmd_name])
        LOG.info("meterentry/%s on %016x: %s", cmd_name, dp.id, json.dumps(body, sort_keys=True))
        return None

    def _groupentry(self, cmd_name: str, body: dict):
        dp = self._dp_of_body(body)
        ofp = dp.ofproto
        commands = {"add": ofp.OFPGC_ADD, "modify": ofp.OFPGC_MODIFY, "delete": ofp.OFPGC_DELETE}
        if cmd_name not in commands:
            raise RestError(404, f"unknown command {cmd_name}")
        ofctl_v1_3.mod_group_entry(dp, body, commands[cmd_name])
        LOG.info("groupentry/%s on %016x: %s", cmd_name, dp.id, json.dumps(body, sort_keys=True))
        return None

    def _clear(self, dpid_text):
        dp = self._dp(dpid_text)
        ofctl_v1_3.mod_flow_entry(dp, {"table_id": dp.ofproto.OFPTT_ALL}, dp.ofproto.OFPFC_DELETE)
        LOG.info("flowentry/clear on %016x", dp.id)
        return None

    def route(self, method: str, path: str, environ):
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2 or parts[0] != "stats":
            raise RestError(404, f"unknown URL {path}")
        what, args = parts[1], parts[2:]
        if method == "GET" and what == "switches" and not args:
            return sorted(self.datapaths)
        if what in ("flowentry", "meterentry", "groupentry") and len(args) == 1 and method == "POST":
            handler = {"flowentry": self._flowentry, "meterentry": self._meterentry,
                       "groupentry": self._groupentry}[what]
            return handler(args[0], self._body(environ))
        if what == "flowentry" and len(args) == 2 and args[0] == "clear" and method == "DELETE":
            return self._clear(args[1])
        if what == "errors" and len(args) == 1 and method == "GET":
            dp = self._dp(args[0])
            return {str(dp.id): list(self.errors.get(dp.id, []))}
        getters = {
            "desc": ofctl_v1_3.get_desc_stats,
            "portdesc": ofctl_v1_3.get_port_desc,
            "meterconfig": ofctl_v1_3.get_meter_config,
            "meter": ofctl_v1_3.get_meter_stats,
            "groupdesc": ofctl_v1_3.get_group_desc,
        }
        if what in getters and len(args) == 1 and method == "GET":
            return getters[what](self._dp(args[0]), self.waiters)
        if what == "port" and len(args) in (1, 2) and method == "GET":
            port = int(args[1]) if len(args) == 2 else None
            return ofctl_v1_3.get_port_stats(self._dp(args[0]), self.waiters, port)
        if what == "flow" and len(args) == 1 and method in ("GET", "POST"):
            flt = self._body(environ) if method == "POST" else {}
            return ofctl_v1_3.get_flow_stats(self._dp(args[0]), self.waiters, flt)
        if what in ("flowentry", "meterentry", "groupentry", "flow", "switches") or what in getters:
            raise RestError(405, f"{method} {path}: wrong method or arguments")
        raise RestError(404, f"unknown URL {path}")

    def wsgi_app(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = re.sub(r"/+", "/", environ.get("PATH_INFO", "/"))
        try:
            result = self.route(method, path, environ)
            status, body = 200, (b"" if result is None else json.dumps(result).encode())
        except RestError as e:
            status, body = e.status, (json.dumps({"error": e.message}) + "\n").encode()
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            status, body = 400, (json.dumps({"error": f"invalid request: {type(e).__name__}: {e}"}) + "\n").encode()
        except Exception as e:  # never kill the server thread
            LOG.exception("error on %s %s", method, path)
            status, body = 500, (json.dumps({"error": f"{type(e).__name__}: {e}"}) + "\n").encode()
        if status != 200:
            LOG.info("%s %s -> %s", method, path, status)
        start_response(_STATUS.get(status, f"{status} Error"),
                       [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]
