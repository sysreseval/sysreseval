ARG VERSION=latest
FROM sysreseval/init:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Supervision image (the SNMP, Nagios, Prometheus, central logs and NetFlow labs): Net-SNMP (agent,
# trap daemon, tools, MIB files), Nagios 4 with its Apache interface, the monitoring plugins and
# NRPE, Prometheus with its node / blackbox / SNMP exporters and Alertmanager, the TLS driver of
# rsyslog, softflowd and nfdump, on top of the init image so that the daemons run under a genuine
# systemd (systemctl restart, journalctl).  The configuration files are those of the Debian
# packages: the students start from them.  Declare the machines like the init ones:
#
#   _machine_specs = {
#        'monitor': {"privileged": True,
#                    "entrypoint": "/sbin/init",
#                    "image": sre_docker_image("monitoring")},
#       .....
#   }
#
# A machine may use the image without /sbin/init (a router whose agent a state starts directly, a
# hidden probe using the tools).
#

ENV SRE_VERSION="sre/monitoring:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# The blackbox exporter sends its ICMP probes as the unprivileged user prometheus: the package
# gives the binary cap_net_raw when asked to.
RUN echo "prometheus-blackbox-exporter prometheus-blackbox-exporter/want_cap_net_raw boolean true" | debconf-set-selections

# prometheus-node-exporter-collectors (a Recommends of the node exporter) is left out: its timers
# run apt / SMART / IPMI / NVMe collectors that mean nothing in a container, and it pulls
# smartmontools, ipmitool and nvme-cli.
RUN apt update && apt install -y \
    snmp \
    snmpd \
    snmptrapd \
    nagios4 \
    monitoring-plugins \
    nagios-nrpe-server \
    nagios-nrpe-plugin \
    prometheus \
    prometheus-node-exporter \
    prometheus-node-exporter-collectors- \
    prometheus-alertmanager \
    prometheus-blackbox-exporter \
    prometheus-snmp-exporter \
    rsyslog-gnutls \
    softflowd \
    nfdump \
    stress-ng

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# MIB files.  Debian ships none of the standard ones (IF-MIB, SNMPv2-MIB, HOST-RESOURCES-MIB...:
# licence of the RFC texts), so the tools would only print numeric OIDs; its snmp-mibs-downloader
# is in non-free, and its installation still fetches files from the Internet (it extracts the RFC
# MIBs from texts it ships, then reports a failed download on a host without Internet access).
# They are taken from the mibs/ directory of the Net-SNMP source archive, at the version of the
# Debian package, checked against its SHA-256 (the files Debian already installed are kept).
# Then "mibs :" (no MIB loaded) is commented out in snmp.conf, and the build fails if a standard
# name does not translate.
ARG NETSNMP_VERSION=5.9.3
ARG NETSNMP_SOURCE_URL=https://downloads.sourceforge.net/project/net-snmp/net-snmp/${NETSNMP_VERSION}/net-snmp-${NETSNMP_VERSION}.tar.gz
ARG NETSNMP_SOURCE_SHA256=2097f29b7e1bf3f1300b4bae52fa2308d0bb8d5d3998dbe02f9462a413a2ef0a
RUN curl -fsSL "${NETSNMP_SOURCE_URL}" -o /tmp/net-snmp.tar.gz \
 && echo "${NETSNMP_SOURCE_SHA256}  /tmp/net-snmp.tar.gz" | sha256sum -c - \
 && mkdir -p /usr/share/snmp/mibs \
 && tar -xzf /tmp/net-snmp.tar.gz -C /usr/share/snmp/mibs --strip-components=2 --skip-old-files \
        --no-same-owner --wildcards "net-snmp-${NETSNMP_VERSION}/mibs/*.txt" \
 && rm -f /tmp/net-snmp.tar.gz \
 && sed -i 's/^mibs :/# mibs :/' /etc/snmp/snmp.conf \
 && test "$(snmptranslate -On SNMPv2-MIB::sysName.0)" = ".1.3.6.1.2.1.1.5.0" \
 && test "$(snmptranslate -On IF-MIB::ifHCInOctets)" = ".1.3.6.1.2.1.31.1.1.1.6"

# Like the init image: no service starts by itself when the entrypoint is /sbin/init (the labs'
# states or the students start the daemons).  Only the systemd links go: the /etc/rc*.d links of
# the SysV scripts these packages also ship start nothing under systemd (the native units win),
# but `systemctl enable` hands them to update-rc.d, which aborts ("no runlevel symlinks to modify")
# when they are missing.  The build checks that enable (then disable) still works on one of them.
RUN rm -f /etc/systemd/system/multi-user.target.wants/snmpd.service \
    /etc/systemd/system/multi-user.target.wants/snmptrapd.service \
    /etc/systemd/system/sockets.target.wants/snmptrapd.socket \
    /etc/systemd/system/multi-user.target.wants/nagios4.service \
    /etc/systemd/system/multi-user.target.wants/nagios-nrpe-server.service \
    /etc/systemd/system/multi-user.target.wants/prometheus.service \
    /etc/systemd/system/multi-user.target.wants/prometheus-node-exporter.service \
    /etc/systemd/system/multi-user.target.wants/prometheus-alertmanager.service \
    /etc/systemd/system/multi-user.target.wants/prometheus-blackbox-exporter.service \
    /etc/systemd/system/multi-user.target.wants/prometheus-snmp-exporter.service \
    /etc/systemd/system/multi-user.target.wants/softflowd.service \
    /etc/systemd/system/multi-user.target.wants/nfdump.service \
 && systemctl enable prometheus-node-exporter >/dev/null 2>&1 \
 && systemctl disable prometheus-node-exporter >/dev/null 2>&1

WORKDIR /

VOLUME /hosthome
VOLUME /shared
