ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/base13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Network device image, on base13 without systemd: the routers, switches, controllers and time
# servers of the network labs.  Debian 13's packages:
#
#   - FRR 10.3 (the routing labs; frr-pythontools, frr-rpki-rtrlib);
#   - iperf 2, ssmping / asmping, smcroute (the multicast lab);
#   - lldpd and lldpcli (the link aggregation / LLDP lab);
#   - stayrtr and rtrclient (rtr-tools) (the BGP security lab);
#   - Open vSwitch 3.5 and the OS-Ken 3.0 controller (the SDN lab);
#   - chrony 4.6 (the NTP lab).
#
# Nothing starts by itself: a lab runs each daemon itself (`smcrouted`, `lldpd`, `stayrtr`,
# lib/sdn.py's ovs_start_cmd() and osken_start_cmd(), `systemctl start chrony`).  A machine of
# this image that runs no router (a host, a switch, a time server) is given `'weight': 1` in its
# spec: params.image_weights counts a router.
#
# (sre/netdev13 merges the former routing-frr13, sdn13 and ntp13 images, 2026-11-25)
#

ENV SRE_VERSION="sre/netdev13:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

# FRR is Debian 13's own package (10.3): deb.frrouting.org publishes no FRR 9 for trixie, and
# Debian's version does not move during the life of the release (what the routing labs teach
# stays true from one build of the image to the next).
#
# Multicast tools: iperf 2 (UDP to a group, -B / -T / -H), ssmping / asmping (ssmpingd answers),
# smcroute (static multicast routes and joins; mcjoin is not packaged in trixie).
#
# RPKI: stayrtr, an RPKI-to-Router cache serving a local JSON file of ROAs to the routers (bgpd -M
# rpki, frr-rpki-rtrlib), and rtrclient (rtr-tools) to query it (its packaged unit would fetch the
# ROAs from the Internet).
#
# Open vSwitch (ovsdb-server, ovs-vswitchd, ovs-vsctl, ovs-ofctl, ovs-appctl, ovs-dpctl) uses the
# kernel datapath (the module openvswitch of the host): a container cannot load a module, but the
# kernel loads it by itself when a process asks for its generic netlink family (`ovs-dpctl show`),
# which lib/sdn.py's ovs_start_cmd() does before ovs-ctl (whose own `modprobe openvswitch` fails
# in a container but is skipped once the module is there).  python3-os-ken: OS-Ken 3.0, the
# maintained fork of the Ryu controller (osken-manager).  tshark (base13) decodes OpenFlow.
#
# The apt lists and caches are removed in the same step (a later step would leave them in this
# layer).
ARG DEBIAN_FRONTEND="noninteractive"
RUN apt-get update \
    && apt-get install -y frr frr-pythontools frr-rpki-rtrlib iperf ssmping smcroute lldpd stayrtr rtr-tools chrony \
    && apt-get install -y --no-install-recommends openvswitch-switch python3-openvswitch python3-os-ken \
    && rm -f /etc/systemd/system/multi-user.target.wants/smcroute.service /etc/rc*.d/S*smcroute* \
             /etc/systemd/system/multi-user.target.wants/lldpd.service /etc/rc*.d/S*lldpd* \
             /etc/systemd/system/multi-user.target.wants/stayrtr.service /etc/rc*.d/S*stayrtr* \
             /etc/systemd/system/multi-user.target.wants/openvswitch-switch.service /etc/rc*.d/S*openvswitch-switch* \
             /etc/systemd/system/multi-user.target.wants/chrony.service /etc/systemd/system/chronyd.service \
             /etc/rc*.d/S*chrony* \
    && apt-get clean \
    && rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

RUN sed -i -e 's/service/no service/' /etc/frr/vtysh.conf \
    && rm /etc/frr/frr.conf

RUN sed -i 's|ExecStart=/usr/lib/frr/frrinit.sh start|ExecStart=/usr/bin/su -c "/usr/lib/frr/frrinit.sh start"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecStop=/usr/lib/frr/frrinit.sh stop|ExecStop=/usr/bin/su -c "/usr/lib/frr/frrinit.sh stop"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecReload=/usr/lib/frr/frrinit.sh reload|ExecReload=/usr/bin/su -c "/usr/lib/frr/frrinit.sh reload"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecStart=/usr/lib/frr/frrinit.sh start|ExecStart=/usr/bin/su -c "/usr/lib/frr/frrinit.sh start"|' /lib/systemd/system/frr\@.service	&& \
	sed -i 's|ExecStop=/usr/lib/frr/frrinit.sh stop|ExecStop=/usr/bin/su -c "/usr/lib/frr/frrinit.sh stop"|' /lib/systemd/system/frr\@.service && \
	sed -i 's|ExecReload=/usr/lib/frr/frrinit.sh reload|ExecReload=/usr/bin/su -c "/usr/lib/frr/frrinit.sh reload"|' /lib/systemd/system/frr\@.service && \
	test "$(cat /lib/systemd/system/frr.service /lib/systemd/system/frr\@.service | grep -c "su -c")" = 6

# chrony.
#
# The clock of a container is the clock of the Docker host: Linux has no time namespace for
# CLOCK_REALTIME.  A container without CAP_SYS_TIME (a Kathara machine that is not privileged)
# cannot change it, and chronyd refuses to start there unless told not to control the clock (-x):
# it then still measures its sources, selects them and serves time, which is what the NTP lab
# needs.  A privileged container has CAP_SYS_TIME: a chronyd without -x would steer the clock of
# the host (a shared pool workstation).  chronyd always runs with -x here (DAEMON_OPTS, read by
# the unit and the init script), and a lab never gives this image to a privileged machine that
# runs chrony.
#
# These changes make it work in a container:
#   - DAEMON_OPTS (/etc/default/chrony): -x, and -l: the messages of chronyd go to
#     /var/log/chrony/chronyd.log (no syslog daemon runs in these containers);
#   - /etc/systemd/system/chrony.service: Debian's unit runs chronyd as User=_chrony under a
#     sandbox the stand-in does not know ("forking start not active"); this one starts chronyd as
#     root, which drops to _chrony itself;
#   - /var/lib/chrony/chrony.drift says 0 ppm +/- 1 ppm (the clock is the host's, disciplined):
#     without it a chronyd starting for the first time knows its frequency to +/- 1000000 ppm and,
#     once synchronised, announces a root dispersion growing by one second per second until its
#     next update, about a minute later, during which its clients reject it;
#   - /etc/init.d/chrony stops by --name instead of --exec (/proc/<pid>/exe of a process of
#     _chrony is not readable without CAP_SYS_PTRACE: `stop` found nothing) and waits for the end
#     of the old daemon (--retry 5: `restart` said "already running").
RUN sed -i 's|^DAEMON_OPTS=.*|DAEMON_OPTS="-F 1 -x -l /var/log/chrony/chronyd.log"|' /etc/default/chrony \
    && grep -q '^DAEMON_OPTS="-F 1 -x -l /var/log/chrony/chronyd.log"$' /etc/default/chrony \
    && sed -i 's/--stop --quiet --oknodo --pidfile $PIDFILE --exec $DAEMON/--stop --quiet --oknodo --retry 5 --pidfile $PIDFILE --name chronyd/' \
           /etc/init.d/chrony \
    && grep -q -- '--retry 5 --pidfile $PIDFILE --name chronyd' /etc/init.d/chrony \
    && install -d -o _chrony -g _chrony -m 0750 /var/lib/chrony /var/log/chrony \
    && echo "0.000000 1.000000" > /var/lib/chrony/chrony.drift \
    && chown _chrony:_chrony /var/lib/chrony/chrony.drift \
    && printf '%s\n' '[Unit]' 'Description=chrony, an NTP client/server (in a container: -x, see /etc/default/chrony)' \
           'Documentation=man:chronyd(8) man:chronyc(1) man:chrony.conf(5)' '' '[Service]' 'Type=forking' \
           'PIDFile=/run/chrony/chronyd.pid' 'EnvironmentFile=-/etc/default/chrony' \
           'ExecStart=/usr/sbin/chronyd $DAEMON_OPTS' '' '[Install]' 'WantedBy=multi-user.target' \
           > /etc/systemd/system/chrony.service

# OS-Ken 3 no longer ships Ryu's sample applications: simple_switch_13 (a reactive learning switch)
# and ofctl_rest (the REST northbound API, Ryu's URLs and JSON documents) written again on the
# library of OS-Ken 3 (os_ken.lib.ofctl_v1_3, os_ken.lib.hub), so that the usual command lines work:
#   osken-manager os_ken.app.simple_switch_13
#   osken-manager os_ken.app.ofctl_rest          (port 8080, OFCTL_REST_HOST / OFCTL_REST_PORT)
COPY os_ken_app/simple_switch_13.py os_ken_app/ofctl_rest.py /usr/lib/python3/dist-packages/os_ken/app/
RUN python3 -c "import os_ken.app.simple_switch_13, os_ken.app.ofctl_rest" \
    && python3 -m compileall -q /usr/lib/python3/dist-packages/os_ken/app

WORKDIR /
