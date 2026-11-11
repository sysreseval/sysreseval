ARG VERSION=latest
FROM sysreseval/init:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# HTTP proxy image (the reverse proxy / load balancer lab): HAProxy, keepalived (VRRP) and
# Varnish (which pulls gcc: it compiles its VCL configuration), plus socat (HAProxy's admin
# socket), hatop and apache2-utils (ab, htpasswd), on top of the init image so that the proxies
# run under a genuine systemd (systemctl reload, journalctl).  nginx, Apache and Caddy come from
# the base image.  Declare the machines like the init ones:
#
#   _machine_specs = {
#        'lb1': {"privileged": True,
#                "entrypoint": "/sbin/init",
#                "image": sre_docker_image("proxy")},
#       .....
#   }
#
# A client machine may use the image without /sbin/init (then only ab / hatop matter).
#

ENV SRE_VERSION="sre/proxy:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

RUN apt update && apt install -y \
    haproxy \
    keepalived \
    varnish \
    socat \
    hatop \
    apache2-utils

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# Like the init image: no service starts by itself when the entrypoint is /sbin/init (the
# students write the configurations and start the daemons).
RUN rm -f /etc/systemd/system/multi-user.target.wants/haproxy.service \
    /etc/systemd/system/multi-user.target.wants/keepalived.service \
    /etc/systemd/system/multi-user.target.wants/varnish.service \
    /etc/systemd/system/multi-user.target.wants/varnishncsa.service

RUN rm -f /etc/rc*/S*haproxy* /etc/rc*/S*keepalived* /etc/rc*/S*varnish*

WORKDIR /

VOLUME /hosthome
VOLUME /shared
