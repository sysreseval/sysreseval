ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/init13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# HTTP proxy image (the reverse proxy / load balancer lab): HAProxy, keepalived (VRRP) and
# Varnish (which pulls gcc: it compiles its VCL configuration), plus socat (HAProxy's admin
# socket), hatop and apache2-utils (ab, htpasswd), on top of the init13 image so that the proxies
# run under a genuine systemd (systemctl reload, journalctl).  nginx, Apache and Caddy come from
# the base13 image.
#
# The forward proxy lab (forward-proxy.py) adds Squid 6: the package squid (the GnuTLS build and
# the helpers: basic_ncsa_auth, basic_ldap_auth, ext_ldap_group_acl...) and squid-openssl (the
# OpenSSL build, the only one with SslBump, and security_file_certgen), /usr/sbin/squid being the
# OpenSSL build; squidclient (the cache manager), squidGuard (URL filter by category), ldap-utils
# (ldapsearch, to test the directory from the proxy) and duktape (duk, a small JavaScript
# interpreter: the grader runs the students' PAC files with it).  Declare the machines like the
# init ones:
#
#   _machine_specs = {
#        'lb1': {"privileged": True,
#                "entrypoint": "/sbin/init",
#                "image": sre_docker_image("proxy13")},
#       .....
#   }
#
# A client machine may use the image without /sbin/init (then only ab / hatop matter).
#

ENV SRE_VERSION="sre/proxy13:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# (keepalived is already in base13; the apt lists and caches are removed in the same step: a
# later step would leave them in this layer)
RUN apt-get update && apt-get install -y \
    haproxy \
    varnish \
    socat \
    hatop \
    apache2-utils \
    squid \
    squid-openssl \
    squidclient \
    squidguard \
    ldap-utils \
    duktape \
 && apt-get clean \
 && rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# Like the init13 image: no service starts by itself when the entrypoint is /sbin/init (the
# students write the configurations and start the daemons).
RUN rm -f /etc/systemd/system/multi-user.target.wants/haproxy.service \
    /etc/systemd/system/multi-user.target.wants/keepalived.service \
    /etc/systemd/system/multi-user.target.wants/varnish.service \
    /etc/systemd/system/multi-user.target.wants/varnishncsa.service \
    /etc/systemd/system/multi-user.target.wants/squid.service

RUN rm -f /etc/rc*/S*haproxy* /etc/rc*/S*keepalived* /etc/rc*/S*varnish* /etc/rc*/S*squid*

WORKDIR /

VOLUME /hosthome
VOLUME /shared
