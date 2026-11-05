ARG VERSION=latest
FROM sysreseval/init:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Electronic mail and LDAP image (the SMTP labs and the LDAP lab): Postfix, Dovecot (IMAP),
# OpenDKIM, policyd-spf and the clients swaks and mutt, plus the LDAP client side, nss-pam-ldapd
# (nslcd, libnss-ldapd, libpam-ldapd; slapd and ldap-utils come from the base image), on top of
# the init image so that the servers run under a genuine systemd (systemctl, journalctl; the
# systemctl replacement of the base image cannot stop an init.d-started slapd).  Declare the
# machines like the init ones:
#
#   _machine_specs = {
#        'mx1': {"privileged": True,
#                "entrypoint": "/sbin/init",
#                "image": sre_docker_image("ldap-mail")},
#       .....
#   }
#
# A client machine may use the image without /sbin/init (then only mutt / swaks matter).
#

ENV SRE_VERSION="sre/ldap-mail:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# "Internet Site" gives the Debian skeleton main.cf (relay restrictions, aliases, snakeoil TLS);
# "No configuration" would leave no main.cf at all.  Postfix replaces exim4 (mail-transport-agent).
# nslcd: a neutral default configuration (its postinst guesses the base from the build host's domain).
RUN echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections \
 && echo "postfix postfix/mailname string localhost.localdomain" | debconf-set-selections \
 && echo "nslcd nslcd/ldap-uris string ldap://127.0.0.1/" | debconf-set-selections \
 && echo "nslcd nslcd/ldap-base string dc=example,dc=com" | debconf-set-selections

RUN apt update && apt install -y \
    postfix \
    postfix-policyd-spf-python \
    dovecot-core \
    dovecot-imapd \
    opendkim \
    opendkim-tools \
    swaks \
    mutt \
    python3-dkim \
    ldap-utils \
    libnss-ldapd \
    libpam-ldapd \
    nslcd

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# Neutralise the build host (the labs or the students set myhostname); IPv6 is disabled in the
# Kathara containers.
RUN postconf -X myhostname && postconf -e 'inet_protocols = ipv4'

# The LDAP client left unconfigured: libnss-ldapd and libpam-ldapd enable themselves at
# installation (ldap in nsswitch.conf, pam_ldap in the common-* files); the LDAP lab's students
# do that configuration.
RUN pam-auth-update --package --remove ldap \
 && sed -i -E 's/^((passwd|group|shadow|netgroup|aliases|ethers|hosts|networks|protocols|rpc|services):.*[[:space:]])ldap[[:space:]]*$/\1/' /etc/nsswitch.conf \
 && sed -i -E 's/[[:space:]]+$//' /etc/nsswitch.conf

# Like the init image: no service starts by itself when the entrypoint is /sbin/init.
RUN rm -f /etc/systemd/system/multi-user.target.wants/postfix.service \
    /etc/systemd/system/multi-user.target.wants/dovecot.service \
    /etc/systemd/system/multi-user.target.wants/opendkim.service \
    /etc/systemd/system/sockets.target.wants/dovecot.socket

RUN rm -f /etc/rc*/S*postfix* /etc/rc*/S*dovecot* /etc/rc*/S*opendkim* /etc/rc*/S*nslcd* /etc/rc*/S*slapd*
