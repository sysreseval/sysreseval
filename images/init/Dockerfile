ARG VERSION=latest
FROM sysreseval/base:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Kathara base image (on which sre/base is build) use instead of systemd a workaround:
# https://github.com/gdraheim/docker-systemctl-replacement
# which add a command /usr/local/bin/systemctl allowing in most case to do: "systemctl start XX",
# "systemctl status CC", etc...
#
# But for some services (bind for example) it's not sufficient.
# This image allow to launch a pid 1 /sbin/init process and have the genuine systemd machinery.
# To use it just defined in your project.py the machines with these options:
#
#   _machine_specs = {
#        'm1': {"privileged": True,
#               "entrypoint": "/sbin/init",
#               "image": sre_docker_image("init")},
#       .....
#   }
#
# you need privileged=True (thus have the parameter allow_privileged_machines=True in params.py)


ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ENV SRE_VERSION="sre/init:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# Prevent all the services to start in the (rare) cases where we need entrypoint=/sbin/init

RUN rm -f /etc/systemd/system/bind9.service /etc/systemd/system/sshd.service \
    /etc/systemd/system/multi-user.target.wants/apache2.service \
    /etc/systemd/system/multi-user.target.wants/cron.service \
    /etc/systemd/system/multi-user.target.wants/mptcp.service \
    /etc/systemd/system/multi-user.target.wants/nfs-client.target \
    /etc/systemd/system/multi-user.target.wants/privoxy.service \
    /etc/systemd/system/multi-user.target.wants/rpcbind.service \
    /etc/systemd/system/multi-user.target.wants/tinyproxy.service \
    /etc/systemd/system/multi-user.target.wants/arpwatch.service \
    /etc/systemd/system/multi-user.target.wants/dnsmasq.service \
    /etc/systemd/system/multi-user.target.wants/named.service \
    /etc/systemd/system/multi-user.target.wants/nfs-server.service \
    /etc/systemd/system/multi-user.target.wants/radvd.service \
    /etc/systemd/system/multi-user.target.wants/unbound.service \
    /etc/systemd/system/multi-user.target.wants/caddy.service \
    /etc/systemd/system/multi-user.target.wants/e2scrub_reap.service \
    /etc/systemd/system/multi-user.target.wants/nginx.service \
    /etc/systemd/system/multi-user.target.wants/remote-fs.target \
    /etc/systemd/system/multi-user.target.wants/ssh.service \
    /etc/systemd/system/multi-user.target.wants/stubby.service \
    /etc/systemd/system/sysinit.target.wants/systemd-resolved.service \
    /etc/systemd/system/sockets.target.wants/rpcbind.socket

RUN rm -f /etc/rc*/S*slapd* /etc/rc*/S*named* /etc/rc*/S*exim*

RUN rm -f /usr/local/bin/systemctl

WORKDIR /tmp

WORKDIR /

VOLUME /hosthome
VOLUME /shared
