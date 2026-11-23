ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/base13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

ENV SRE_VERSION="sre/routing-frr:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

# FRR is Debian 13's own package (10.3): deb.frrouting.org publishes no FRR 9 for trixie, and
# Debian's version does not move during the life of the release (what the routing labs teach
# stays true from one build of the image to the next).
ARG DEBIAN_FRONTEND="noninteractive"
RUN apt update && apt install -y frr frr-pythontools frr-rpki-rtrlib

RUN sed -i -e 's/service/no service/' /etc/frr/vtysh.conf \
    && rm /etc/frr/frr.conf

# Multicast tools (the multicast lab): iperf 2 (UDP to a group, -B / -T / -H), ssmping / asmping
# (ssmpingd answers), smcroute (static multicast routes and joins; mcjoin is not packaged in
# trixie).  smcroute is a daemon: nothing starts it, a lab runs `smcrouted` itself.
RUN apt update && apt install -y iperf ssmping smcroute \
    && rm -f /etc/systemd/system/multi-user.target.wants/smcroute.service /etc/rc*.d/S*smcroute*

# LLDP (the link aggregation / LLDP lab): lldpd and lldpcli.  lldpd is a daemon: nothing starts
# it, a lab runs `lldpd` itself (its dependencies are already in base13: about 0.6 MB).
RUN apt update && apt install -y lldpd \
    && rm -f /etc/systemd/system/multi-user.target.wants/lldpd.service /etc/rc*.d/S*lldpd*

# RPKI (the BGP security lab): stayrtr, an RPKI-to-Router cache serving a local JSON file of ROAs to
# the routers (bgpd -M rpki, frr-rpki-rtrlib above), and rtrclient (rtr-tools) to query it.  stayrtr
# is a daemon: nothing starts it (its packaged unit would fetch the ROAs from the Internet), a lab
# runs `stayrtr` itself (about 27 MB, no dependency beyond base13).
RUN apt update && apt install -y stayrtr rtr-tools \
    && rm -f /etc/systemd/system/multi-user.target.wants/stayrtr.service /etc/rc*.d/S*stayrtr*

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

RUN sed -i 's|ExecStart=/usr/lib/frr/frrinit.sh start|ExecStart=/usr/bin/su -c "/usr/lib/frr/frrinit.sh start"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecStop=/usr/lib/frr/frrinit.sh stop|ExecStop=/usr/bin/su -c "/usr/lib/frr/frrinit.sh stop"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecReload=/usr/lib/frr/frrinit.sh reload|ExecReload=/usr/bin/su -c "/usr/lib/frr/frrinit.sh reload"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecStart=/usr/lib/frr/frrinit.sh start|ExecStart=/usr/bin/su -c "/usr/lib/frr/frrinit.sh start"|' /lib/systemd/system/frr\@.service	&& \
	sed -i 's|ExecStop=/usr/lib/frr/frrinit.sh stop|ExecStop=/usr/bin/su -c "/usr/lib/frr/frrinit.sh stop"|' /lib/systemd/system/frr\@.service && \
	sed -i 's|ExecReload=/usr/lib/frr/frrinit.sh reload|ExecReload=/usr/bin/su -c "/usr/lib/frr/frrinit.sh reload"|' /lib/systemd/system/frr\@.service && \
	test "$(cat /lib/systemd/system/frr.service /lib/systemd/system/frr\@.service | grep -c "su -c")" = 6
