ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/base13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Kathara base image (on which sre/base13 is build) use instead of systemd a workaround:
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
#               "image": sre_docker_image("init13")},
#       .....
#   }
#
# you need privileged=True (thus have the parameter allow_privileged_machines=True in params.py)


ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ENV SRE_VERSION="sre/init13:${VERSION}"
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
    /etc/systemd/system/multi-user.target.wants/openvpn.service \
    /etc/systemd/system/multi-user.target.wants/strongswan.service \
    /etc/systemd/system/multi-user.target.wants/strongswan-starter.service \
    /etc/systemd/system/multi-user.target.wants/keepalived.service \
    /etc/systemd/system/multi-user.target.wants/fail2ban.service \
    /etc/systemd/system/multi-user.target.wants/suricata.service \
    /etc/systemd/system/sysinit.target.wants/systemd-resolved.service \
    /etc/systemd/system/sockets.target.wants/rpcbind.socket

# The openvpn package also ships a generator that starts an openvpn@<name> instance for every
# /etc/openvpn/<name>.conf at boot (AUTOSTART="all"): the labs start their tunnels explicitly
# (openvpn-server@ / openvpn-client@ on /etc/openvpn/{server,client}/).
RUN rm -f /lib/systemd/system-generators/openvpn-generator

RUN rm -f /etc/rc*/S*slapd* /etc/rc*/S*named* /etc/rc*/S*exim* /etc/rc*/S*openvpn*

# Debian 13 ships native units for slapd and exim4 (sysv scripts on Debian 12), and keepalived
# pulls ipvsadm: none starts by itself, as on init12 (Debian 12).
RUN rm -f /etc/systemd/system/multi-user.target.wants/slapd.service \
    /etc/systemd/system/multi-user.target.wants/exim4.service \
    /etc/systemd/system/multi-user.target.wants/ipvsadm.service \
    /etc/systemd/system/timers.target.wants/exim4-base.timer

# Debian 13 mounts a tmpfs on /tmp (tmp.mount, a plain directory on Debian 12).  The files a lab
# state copies into /tmp of a machine are written by Docker to the container's own filesystem,
# under that mount, where no process of the machine sees them: /tmp stays a plain directory.
RUN ln -sf /dev/null /etc/systemd/system/tmp.mount

# A privileged machine is not confined like the others: /sys and /proc/sys are read-write and
# /dev holds the device nodes of the host, so the systemd of the machine takes itself for the
# init of a real host and acts on the HOST.  Seen on a workstation with a camera (2026-11-25,
# the three privileged machines of the dhcp lab): the coldplug of systemd-udev-trigger wrote
# "add" to the uevent file of every device of the host, the host's udev replayed them all and
# the wireplumber of the logged-in user aborted on its camera (one core dump per machine);
# systemd-sysctl set the host's kernel.core_pattern to "core" (Debian 13), so those dumps were
# written in the home directory; a getty of the machine took the host's tty1 and its logind
# watched the host's power and sleep keys.  The guard keeps what concerns the machine itself:
# - the coldplug is limited to the network interfaces, which are the machine's own (their
#   uevents stay in its network namespace): udev still tags them, so allow-hotplug and the
#   per-interface sysctls of 99-systemd.rules work as before;
# - systemd-sysctl applies the net.* keys only (kernel.*, fs.* and vm.* are the host's);
# - no getty on a virtual terminal (console-getty, the machine's own console, stays); logind
#   reserves none and ignores the keys and the lid of the host;
# - systemd-binfmt registers nothing (binfmt_misc is the host's).
# This block is the same in init12 and init13: tests/test_init_images.py.
RUN mkdir -p /etc/systemd/system/systemd-udev-trigger.service.d \
        /etc/systemd/system/systemd-sysctl.service.d /etc/systemd/logind.conf.d \
    && printf '%s\n' '[Service]' 'ExecStart=' \
        'ExecStart=-udevadm trigger --type=devices --action=add --subsystem-match=net' \
        > /etc/systemd/system/systemd-udev-trigger.service.d/sre-host-guard.conf \
    && printf '%s\n' '[Service]' 'ExecStart=' \
        'ExecStart=/usr/lib/systemd/systemd-sysctl --prefix=/net' \
        > /etc/systemd/system/systemd-sysctl.service.d/sre-host-guard.conf \
    && printf '%s\n' '[Login]' 'NAutoVTs=0' 'ReserveVT=0' 'HandlePowerKey=ignore' \
        'HandlePowerKeyLongPress=ignore' 'HandleRebootKey=ignore' 'HandleSuspendKey=ignore' \
        'HandleHibernateKey=ignore' 'HandleLidSwitch=ignore' \
        'HandleLidSwitchExternalPower=ignore' 'HandleLidSwitchDocked=ignore' \
        > /etc/systemd/logind.conf.d/sre-host-guard.conf \
    && rm -f /etc/systemd/system/getty.target.wants/getty@tty1.service \
    && ln -sf /dev/null /etc/systemd/system/getty@.service \
    && ln -sf /dev/null /etc/systemd/system/autovt@.service \
    && ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service \
    && ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount

RUN rm -f /usr/local/bin/systemctl

WORKDIR /tmp

WORKDIR /

VOLUME /hosthome
VOLUME /shared
