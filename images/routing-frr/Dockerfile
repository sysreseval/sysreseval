ARG VERSION=latest
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/base13:${VERSION}
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

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

RUN sed -i 's|ExecStart=/usr/lib/frr/frrinit.sh start|ExecStart=/usr/bin/su -c "/usr/lib/frr/frrinit.sh start"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecStop=/usr/lib/frr/frrinit.sh stop|ExecStop=/usr/bin/su -c "/usr/lib/frr/frrinit.sh stop"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecReload=/usr/lib/frr/frrinit.sh reload|ExecReload=/usr/bin/su -c "/usr/lib/frr/frrinit.sh reload"|' /lib/systemd/system/frr.service && \
	sed -i 's|ExecStart=/usr/lib/frr/frrinit.sh start|ExecStart=/usr/bin/su -c "/usr/lib/frr/frrinit.sh start"|' /lib/systemd/system/frr\@.service	&& \
	sed -i 's|ExecStop=/usr/lib/frr/frrinit.sh stop|ExecStop=/usr/bin/su -c "/usr/lib/frr/frrinit.sh stop"|' /lib/systemd/system/frr\@.service && \
	sed -i 's|ExecReload=/usr/lib/frr/frrinit.sh reload|ExecReload=/usr/bin/su -c "/usr/lib/frr/frrinit.sh reload"|' /lib/systemd/system/frr\@.service && \
	test "$(cat /lib/systemd/system/frr.service /lib/systemd/system/frr\@.service | grep -c "su -c")" = 6
