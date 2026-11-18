ARG VERSION=latest
FROM sysreseval/base:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

ENV SRE_VERSION="sre/routing-frr:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

RUN curl -s https://deb.frrouting.org/frr/keys.asc | apt-key add -
   
RUN echo "deb https://deb.frrouting.org/frr $(lsb_release -s -c) \"frr-9\"" | tee -a /etc/apt/sources.list.d/frr.list 

ARG DEBIAN_FRONTEND="noninteractive"
RUN apt update && apt install -y frr frr-pythontools frr-rpki-rtrlib

RUN sed -i -e 's/service/no service/' /etc/frr/vtysh.conf \
    && rm /etc/frr/frr.conf

# Multicast tools (the multicast lab): iperf 2 (UDP to a group, -B / -T / -H), ssmping / asmping
# (ssmpingd answers), smcroute (static multicast routes and joins; mcjoin is not packaged before
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
	sed -i 's|ExecReload=/usr/lib/frr/frrinit.sh reload|ExecReload=/usr/bin/su -c "/usr/lib/frr/frrinit.sh reload"|' /lib/systemd/system/frr\@.service
