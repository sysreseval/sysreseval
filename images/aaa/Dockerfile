ARG VERSION=latest
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/init13:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# AAA image (the AAA lab: RADIUS, 802.1X, two-factor TOTP, device administration, Kerberos):
# FreeRADIUS (+ its LDAP module and radclient / radtest), hostapd (its "wired" driver is the
# 802.1X authenticator of a Linux switch), wpa_supplicant (wired supplicant) and eapol_test, the MIT
# Kerberos KDC, kadmind and clients, pam_krb5, pam_radius_auth, Apache's mod_auth_gssapi (SPNEGO),
# oathtool (TOTP codes) and the LDAP clients, on top of the init13 image so that the servers run
# under a genuine systemd.  slapd, sshd and Apache come from the base13 image.  Declare the machines
# like the init ones:
#
#   _machine_specs = {
#        'radius': {"privileged": True,
#                   "entrypoint": "/sbin/init",
#                   "image": sre_docker_image("aaa")},
#       .....
#   }
#
# A client machine may use the image without /sbin/init (radclient, eapol_test, kinit, curl).
#

ENV SRE_VERSION="sre/aaa:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# krb5-config writes /etc/krb5.conf from these answers: a neutral realm without servers (the labs
# write their own krb5.conf).
RUN echo "krb5-config krb5-config/default_realm string EXAMPLE.ORG" | debconf-set-selections \
 && echo "krb5-config krb5-config/add_servers_realm string EXAMPLE.ORG" | debconf-set-selections \
 && echo "krb5-config krb5-config/add_servers boolean false" | debconf-set-selections \
 && echo "krb5-config krb5-config/read_conf boolean true" | debconf-set-selections \
 && echo "krb5-admin-server krb5-admin-server/kadmind boolean false" | debconf-set-selections \
 && echo "krb5-kdc krb5-kdc/debconf boolean false" | debconf-set-selections

RUN apt update && apt install -y \
    freeradius \
    freeradius-utils \
    freeradius-ldap \
    hostapd \
    wpasupplicant \
    eapoltest \
    krb5-kdc \
    krb5-admin-server \
    krb5-user \
    libpam-krb5 \
    libapache2-mod-auth-gssapi \
    libpam-radius-auth \
    oathtool \
    ldap-utils

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# pam_krb5 enables itself at installation (krb5 in the common-* files): the students do it.
RUN pam-auth-update --package --remove krb5

# mod_auth_gssapi is enabled at installation: the students enable it.
RUN a2dismod -f auth_gssapi || true

# The configuration of FreeRADIUS as installed (bootstrap certificates included), so that a lab can
# put a server back in its installed state.
RUN mkdir -p /usr/local/share/sre && cp -a /etc/freeradius /usr/local/share/sre/freeradius-pristine

# The per-interface units of hostapd and wpa_supplicant depend on the udev device unit of the
# interface (BindsTo= / Requires= sys-subsystem-net-devices-%i.device), which never becomes active
# in a container (no udev): systemd stops hostapd@eth1 as soon as it has started.  Copies without
# that dependency in /etc/systemd/system take precedence.
RUN for u in hostapd@ wpa_supplicant-wired@ wpa_supplicant@ wpa_supplicant-nl80211@; do \
        sed -e '/^BindsTo=sys-subsystem-net-devices/d' -e '/^Requires=sys-subsystem-net-devices/d' \
            -e '/^After=sys-subsystem-net-devices/d' -e 's/ sys-subsystem-net-devices-%i.device//' \
            /lib/systemd/system/$u.service > /etc/systemd/system/$u.service; \
    done

# Like the init13 image: no service starts by itself when the entrypoint is /sbin/init.
RUN rm -f /etc/systemd/system/multi-user.target.wants/freeradius.service \
    /etc/systemd/system/multi-user.target.wants/hostapd.service \
    /etc/systemd/system/multi-user.target.wants/krb5-kdc.service \
    /etc/systemd/system/multi-user.target.wants/krb5-admin-server.service \
    /etc/systemd/system/multi-user.target.wants/wpa_supplicant.service \
    /etc/systemd/system/dbus-fi.w1.wpa_supplicant1.service

RUN rm -f /etc/rc*/S*freeradius* /etc/rc*/S*hostapd* /etc/rc*/S*krb5*

WORKDIR /

VOLUME /hosthome
VOLUME /shared
