FROM kathara/base
LABEL org.opencontainers.image.authors="SysResEval"


ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ARG VERSION
ENV SRE_VERSION="sre/base:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"


ARG DEBIAN_FRONTEND="noninteractive"
RUN apt update
RUN apt upgrade -y
RUN apt install -y \
    lsof \
    mg \
    unbound \
    unbound-anchor \
    knot-dnsutils \
    stubby \
    tinyproxy \
    privoxy \
    vlan \
    arpwatch \
    nmap \
    ettercap-text-only \
    iotop \
    jc \
    jq \
    xauth \
    x11-apps \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    libfreetype6 \
    libfontconfig1 \
    libglib2.0-0 \
    libsm6 \
    libice6 \
    libgtk-3-0 \
    libdbus-1-3 \
    libnss3 \
    libasound2 \
    libxrandr2 \
    libxdamage1 \
    libxfixes3 \
    libxcomposite1 \
    libxkbcommon0 \
    libegl1 \
    sudo \
    x11-apps \
    wireshark-common \
    tshark \
    wireshark \
    mptcpize \
    nginx-full \
    caddy \
    xterm \
    lxterminal \
    elinks \
    firefox-esr \
    libapache2-mod-php \
    dsh \
    rsyslog \
    nfs-kernel-server \
    systemd-resolved \
    nftables \
    ifupdown \
    isc-dhcp-server \
    isc-dhcp-relay \
    isc-dhcp-server-ldap \
    slapd \
    nfs-kernel-server \
    systemd-resolved

WORKDIR /tmp
# web
RUN rm -f /var/www/html/index.html
RUN cat <<'EOF' >/var/www/html/index.php
<html><body>
<table>
<tr><td>Server</td><td><?php echo $_SERVER['SERVER_ADDR']; ?></td><td>port <?php echo $_SERVER['SERVER_PORT']; ?></td></tr>
<tr><td>Client</td><td><?php echo $_SERVER['REMOTE_ADDR']; ?></td><td>port <?php echo $_SERVER['REMOTE_PORT']; ?></td></tr>
</table>
</body></html>
EOF

# Smallstep
RUN curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg -o /etc/apt/keyrings/smallstep.asc\
   && echo "Types: deb\n\
URIs: https://packages.smallstep.com/stable/debian\n\
Suites: debs\n\
Components: main\n\
Signed-By: /etc/apt/keyrings/smallstep.asc\n" > /etc/apt/sources.list.d/smallstep.sources\
   && apt-get update && apt-get -y install step-cli step-ca

#RUN apt install -y \
#    wireshark \
#    ettercap-graphical







COPY .bashrc /root/.bashrc

# X11 forwarding to the host: if sre-wrapper passed us the host's X magic cookie,
# point DISPLAY at the host and merge the cookie so GUI apps started in a
# container show up on the host's X server.  Appended to /root/.bashrc and to
# /etc/skel/.bashrc so every user created below (useradd -m seeds their home
# from /etc/skel) gets it too.
RUN cat <<'EOF' | tee -a /root/.bashrc >> /etc/skel/.bashrc

if [ -n "$SRE_XAUTH_COOKIE" ]; then
    export DISPLAY="${SRE_HOST_IP}:0"
    xauth add "$DISPLAY" . "$SRE_XAUTH_COOKIE" 2>/dev/null
fi
EOF


RUN useradd -m -s /bin/bash "etudiant" \
    && echo "etudiant:etudiant" | chpasswd \
    && useradd -m -s /bin/bash "student" \
    && echo "student:student" | chpasswd \
    && echo "root:root" | chpasswd

RUN useradd -m -s /bin/bash "admin" \
    && echo "admin:admin" | chpasswd \
    && echo "admin  ALL=(ALL:ALL) ALL\n" >/etc/sudoers.d/admin


# allow root login
RUN sed -i 's/.*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#X11UseLocalhost yes/X11UseLocalhost no/' /etc/ssh/sshd_config

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

WORKDIR /

VOLUME /hosthome
VOLUME /shared
