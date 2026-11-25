ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/init13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Scanning and hardening image (the lab lab/sre/_DRAFT_misc/scan-hardening.py): the legacy services
# a scan finds and a hardening closes, and the tools that compare scans.  nmap itself is already in
# base13.  Debian 13's packages, about 25 MB on top of init13:
#
#   - vsftpd (an FTP server, anonymous access when the lab enables it);
#   - openbsd-inetd + inetutils-telnetd (a telnet server started by inetd);
#   - snmpd + snmp (the Net-SNMP agent and its command-line tools, without the MIB files: the
#     labs use numeric OIDs, see lib/snmp.py);
#   - redis-server + redis-tools (a key-value store, and redis-cli);
#   - tftpd-hpa (a TFTP server);
#   - ndiff (compares two nmap XML outputs) and xsltproc (an nmap XML output to an HTML report
#     with /usr/share/nmap/nmap.xsl).
#
# The hardening targets run it as an init machine (the daemons under a genuine systemd):
#
#   _machine_specs = {
#        'legacy': {"privileged": True,
#                   "entrypoint": "/sbin/init",
#                   "image": sre_docker_image("scan13")},
#       .....
#   }
#
# A machine may use the image without /sbin/init (the scanning station, hidden hosts whose
# daemons a state starts directly, a probe using the tools).
#

ENV SRE_VERSION="sre/scan13:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"
RUN apt update && apt install -y --no-install-recommends \
    vsftpd \
    openbsd-inetd \
    inetutils-telnetd \
    snmpd \
    snmp \
    redis-server \
    redis-tools \
    tftpd-hpa \
    ndiff \
    xsltproc

# Like the init13 image: no service starts by itself when the entrypoint is /sbin/init (the labs'
# states or the students start the daemons).  Only the systemd links go: the /etc/rc*.d links of
# the SysV scripts these packages also ship start nothing under systemd (the native units win),
# but `systemctl enable` hands them to update-rc.d, which aborts ("no runlevel symlinks to modify")
# when they are missing.  The build checks that enable (then disable) still works on one of them.
RUN rm -f /etc/systemd/system/multi-user.target.wants/vsftpd.service \
    /etc/systemd/system/multi-user.target.wants/inetd.service \
    /etc/systemd/system/multi-user.target.wants/snmpd.service \
    /etc/systemd/system/multi-user.target.wants/redis-server.service \
    /etc/systemd/system/multi-user.target.wants/tftpd-hpa.service \
    /etc/systemd/system/redis.service \
 && systemctl enable vsftpd >/dev/null 2>&1 \
 && systemctl disable vsftpd >/dev/null 2>&1 \
 && test -z "$(ls /etc/systemd/system/multi-user.target.wants/ | grep -E 'vsftpd|inetd|snmpd|redis|tftpd')"

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

WORKDIR /

VOLUME /hosthome
VOLUME /shared
