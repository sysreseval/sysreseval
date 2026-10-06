ARG VERSION=latest
FROM sysreseval/init:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Electronic mail image (SMTP labs): Postfix, Dovecot (IMAP), OpenDKIM, policyd-spf and the
# clients swaks and mutt, on top of the init image so that the servers run under a genuine
# systemd (systemctl, journalctl).  Declare the machines like the init ones:
#
#   _machine_specs = {
#        'mx1': {"privileged": True,
#                "entrypoint": "/sbin/init",
#                "image": sre_docker_image("mail")},
#       .....
#   }
#
# A client machine may use the image without /sbin/init (then only mutt / swaks matter).
#

ENV SRE_VERSION="sre/mail:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# "Internet Site" gives the Debian skeleton main.cf (relay restrictions, aliases, snakeoil TLS);
# "No configuration" would leave no main.cf at all.  Postfix replaces exim4 (mail-transport-agent).
RUN echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections \
 && echo "postfix postfix/mailname string localhost.localdomain" | debconf-set-selections

RUN apt update && apt install -y \
    postfix \
    postfix-policyd-spf-python \
    dovecot-core \
    dovecot-imapd \
    opendkim \
    opendkim-tools \
    swaks \
    mutt \
    python3-dkim

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# Neutralise the build host (the labs or the students set myhostname); IPv6 is disabled in the
# Kathara containers.
RUN postconf -X myhostname && postconf -e 'inet_protocols = ipv4'

# Like the init image: no service starts by itself when the entrypoint is /sbin/init.
RUN rm -f /etc/systemd/system/multi-user.target.wants/postfix.service \
    /etc/systemd/system/multi-user.target.wants/dovecot.service \
    /etc/systemd/system/multi-user.target.wants/opendkim.service \
    /etc/systemd/system/sockets.target.wants/dovecot.socket

RUN rm -f /etc/rc*/S*postfix* /etc/rc*/S*dovecot* /etc/rc*/S*opendkim*
