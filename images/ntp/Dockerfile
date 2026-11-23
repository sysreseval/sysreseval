ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/base13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

ENV SRE_VERSION="sre/ntp:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

# chrony (the NTP lab): Debian 13's package (4.6), about 0.7 MB, its dependencies already in base13.
#
# The clock of a container is the clock of the Docker host: Linux has no time namespace for
# CLOCK_REALTIME.  A container without CAP_SYS_TIME (a Kathara machine that is not privileged)
# cannot change it, and chronyd refuses to start there unless told not to control the clock (-x):
# it then still measures its sources, selects them and serves time, which is what the lab needs.
# A privileged container has CAP_SYS_TIME: a chronyd without -x would steer the clock of the host
# (a shared pool workstation), so the labs never give a privileged machine this image.
#
# Nothing starts chronyd: a lab runs `systemctl start chrony` (the stand-in of base13) or
# `service chrony start` itself.  These changes make it work in a container:
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
ARG DEBIAN_FRONTEND="noninteractive"
RUN apt update && apt install -y chrony \
    && rm -f /etc/systemd/system/multi-user.target.wants/chrony.service \
             /etc/systemd/system/chronyd.service /etc/rc*.d/S*chrony* \
    && sed -i 's|^DAEMON_OPTS=.*|DAEMON_OPTS="-F 1 -x -l /var/log/chrony/chronyd.log"|' /etc/default/chrony \
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

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*
