#
# Debian 13 (trixie) twin of sysreseval/base12.
#
# kathara/base (the parent of sysreseval/base12) is still Debian 12, so this image rebuilds on
# debian:13 what Kathara adds (kathara/core then kathara/base:
# https://github.com/KatharaFramework/Docker-Images) and then everything sysreseval/base12 adds,
# under the Debian 13 package names.  Differences with sysreseval/base12:
#
#   - nginx comes from nginx.org (stable 1.30, built against OpenSSL 3.5's QUIC API: HTTP/3 with
#     0-RTT), not Debian's nginx-full: conf.d layout, user nginx, no Debian dynamic modules; a
#     Debian-style /etc/nginx/sites-enabled include and default site are added;
#   - curl 8.14 does HTTP/3 (--http3, --http3-only), python3-aioquic and conntrack are
#     installed (the QUIC lab);
#   - suricata comes from Debian main (no backports);
#   - scapy and tabulate are Debian's packages (kathara/core pip-installs them);
#   - systemd-resolved is installed but disabled (see below: the dhclient hooks of its Debian 13
#     package);
#   - the recent iproute2 built from git is copied last, after every apt operation.
#
# A build host whose firewall lets deb.debian.org through but not git.kernel.org, nginx.org or
# packages.smallstep.com (a room workstation with its Internet access off) takes those files
# from cache/ instead, where they are dropped by hand before the build (see cache/README):
#
#   cache/iproute2-<version>.tar.xz       (built instead of the latest git tag)
#   cache/nginx_<version>~trixie_amd64.deb
#   cache/step-cli_<version>_amd64.deb  cache/step-ca_<version>_amd64.deb
#   cache/systemctl3.py
#
# This is the default image of the labs (params.sre_docker_image()); a machine that needs a
# genuine systemd names sre_docker_image("init13").
#

# --- iproute2, latest release (as kathara/core does) ----------------------------------------
FROM debian:13 AS iproute

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    bison \
    build-essential \
    ca-certificates \
    flex \
    git \
    libbpf-dev \
    libcap-dev \
    libmnl-dev \
    pkg-config

WORKDIR /tmp
COPY cache/ /cache/

RUN mkdir output && \
    if ls /cache/iproute2-*.tar.xz >/dev/null 2>&1; then \
        tar -xJf "$(ls /cache/iproute2-*.tar.xz | sort -V | tail -1)" && mv iproute2-* iproute2; \
    else \
        git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git && \
        (cd iproute2 && git checkout tags/$(git describe --tags --abbrev=0)); \
    fi && \
    cd iproute2 && \
    ./configure && \
    make -j$(nproc) && \
    DESTDIR=/tmp/output make install

# --- the image ------------------------------------------------------------------------------
FROM debian:13
LABEL org.opencontainers.image.authors="SysResEval"

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ARG VERSION
ENV SRE_VERSION="sre/base13:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# kathara/core
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    apt-transport-https \
    arping \
    arptables \
    bridge-utils \
    curl \
    diffutils \
    dnsutils \
    dublin-traceroute \
    ethtool \
    expect \
    git \
    gnupg \
    hping3 \
    htop \
    iperf3 \
    iptables \
    iputils-ping \
    iputils-tracepath \
    isc-dhcp-client \
    less \
    libbpf1 \
    libelf1 \
    links \
    lsb-base \
    lsb-release \
    make \
    man-db \
    mtr-tiny \
    nano \
    ndisc6 \
    net-tools \
    netbase \
    netcat-openbsd \
    openssh-client \
    openssh-server \
    openssh-sftp-server \
    openssl \
    procps \
    python3-pip \
    radvd \
    rsync \
    screen \
    sed \
    systemd-userdbd \
    tar \
    tcpdump \
    telnet \
    tmux \
    traceroute \
    tree \
    vim \
    wget

COPY cache/ /cache/

# (kathara/core ADDs it; a RUN curl because the Docker daemon of some build hosts cannot fetch an
# ADD URL)
RUN if [ -f /cache/systemctl3.py ]; then cp /cache/systemctl3.py /usr/local/bin/systemctl; \
    else curl -fsSL https://raw.githubusercontent.com/gdraheim/docker-systemctl-replacement/master/files/docker/systemctl3.py \
            -o /usr/local/bin/systemctl; fi \
    && chmod +x /usr/local/bin/systemctl

# (kathara/core: pip install scapy tabulate; PyPI is not reachable from every build host)
RUN apt-get install -y --no-install-recommends python3-scapy python3-tabulate

RUN mkdir /var/kathara

# kathara/base
RUN apt-get install -y --no-install-recommends \
    apache2 \
    apache2-bin \
    bind9 \
    bind9-utils \
    dnsmasq

RUN ln -sf /etc/init.d/named /etc/init.d/bind

COPY apache2.service /usr/lib/systemd/system/apache2.service

# nginx from nginx.org (stable): HTTP/3 with OpenSSL 3.5's QUIC API (0-RTT).  The signing key
# must hold the fingerprint published on https://nginx.org/en/linux_packages.html (gpg is given
# a throwaway home directory: with --dry-run it does not create /root/.gnupg and stops on
# "directory does not exist" after the first line of the listing).  Without access to nginx.org,
# the package dropped in cache/.
RUN if ls /cache/nginx_*~trixie_$(dpkg --print-architecture).deb >/dev/null 2>&1; then \
        apt-get install -y "$(ls /cache/nginx_*~trixie_$(dpkg --print-architecture).deb | sort -V | tail -1)"; \
    else \
        curl -fsSL https://nginx.org/keys/nginx_signing.key -o /tmp/nginx_signing.key \
        && mkdir -m 700 /tmp/gnupg \
        && gpg --homedir /tmp/gnupg --dry-run --quiet --no-keyring --import --import-options import-show /tmp/nginx_signing.key \
           | grep -q 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62 \
        && gpg --homedir /tmp/gnupg --dearmor < /tmp/nginx_signing.key > /usr/share/keyrings/nginx-archive-keyring.gpg \
        && rm -rf /tmp/gnupg /tmp/nginx_signing.key \
        && echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian trixie nginx" \
           > /etc/apt/sources.list.d/nginx.list \
        && printf 'Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n' \
           > /etc/apt/preferences.d/99nginx \
        && apt-get update && apt-get install -y nginx; \
    fi \
    && nginx -V 2>&1 | grep -q -- --with-http_v3_module

# sysreseval/base12
RUN apt-get install -y \
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
    libglib2.0-0t64 \
    libsm6 \
    libice6 \
    libgtk-3-0t64 \
    libdbus-1-3 \
    libnss3 \
    libasound2t64 \
    libxrandr2 \
    libxdamage1 \
    libxfixes3 \
    libxcomposite1 \
    libxkbcommon0 \
    libegl1 \
    sudo \
    wireshark-common \
    tshark \
    wireshark \
    mptcpize \
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
    iptables \
    ifupdown \
    isc-dhcp-server \
    isc-dhcp-relay \
    isc-dhcp-server-ldap \
    slapd \
    openvpn \
    wireguard \
    easy-rsa \
    strongswan-swanctl \
    charon-systemd \
    strongswan-pki \
    libcharon-extra-plugins \
    libstrongswan-extra-plugins \
    libstrongswan-standard-plugins \
    keepalived \
    fail2ban \
    suricata \
    python3-aioquic \
    conntrack

# nginx.org's layout plus the Debian one, so that a site written for Debian's nginx loads too:
# /etc/nginx/sites-enabled/* included next to conf.d/*.conf, and Debian's default site in
# place of nginx.org's conf.d/default.conf.
RUN mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets \
    && sed -i 's|^\([[:space:]]*\)include /etc/nginx/conf.d/\*\.conf;|&\n\1include /etc/nginx/sites-enabled/*;|' /etc/nginx/nginx.conf \
    && grep -q 'include /etc/nginx/sites-enabled/\*;' /etc/nginx/nginx.conf \
    && rm -f /etc/nginx/conf.d/default.conf
RUN cat <<'EOF' >/etc/nginx/sites-available/default
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}
}
EOF
RUN ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

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

# Smallstep (without access to packages.smallstep.com: the two packages dropped in cache/)
RUN if ls /cache/step-cli_*.deb /cache/step-ca_*.deb >/dev/null 2>&1; then \
        apt-get install -y "$(ls /cache/step-cli_*.deb | sort -V | tail -1)" "$(ls /cache/step-ca_*.deb | sort -V | tail -1)"; \
    else \
        mkdir -p /etc/apt/keyrings \
        && curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg -o /etc/apt/keyrings/smallstep.asc \
        && printf 'Types: deb\nURIs: https://packages.smallstep.com/stable/debian\nSuites: debs\nComponents: main\nSigned-By: /etc/apt/keyrings/smallstep.asc\n' \
           > /etc/apt/sources.list.d/smallstep.sources \
        && apt-get update && apt-get -y install step-cli step-ca; \
    fi

COPY .bashrc /root/.bashrc

# X11 forwarding to the host (see sysreseval/base12): SRE_XAUTH_COOKIE / SRE_DISPLAY / SRE_HOST_IP
# are set by sre-wrapper or the web agent.
RUN cat <<'EOF' | tee -a /root/.bashrc >> /etc/skel/.bashrc

if [ -n "$SRE_XAUTH_COOKIE" ]; then
    export DISPLAY="${SRE_DISPLAY:-${SRE_HOST_IP}:0}"
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

# Debian 13's systemd-resolved package ships dhclient hooks (/etc/dhcp/dhclient-*-hooks.d/resolved*)
# that leave /etc/resolv.conf alone whenever the unit is enabled, which it is as installed: resolved
# does not run in these containers, so a DHCP client would end up without any name server.  The
# unit is disabled (its wants link and its D-Bus alias): dhclient writes resolv.conf itself, as on
# Debian 12, whose package has no such hook.
RUN rm -f /etc/systemd/system/sysinit.target.wants/systemd-resolved.service \
          /etc/systemd/system/dbus-org.freedesktop.resolve1.service \
    && ! systemctl is-enabled systemd-resolved >/dev/null 2>&1

# The recent iproute2 last, so that no apt operation above puts Debian's back; marked installed
# in the dpkg database (as kathara/core does) so that apt does not overwrite it.
COPY --from=iproute /tmp/output/sbin /sbin
COPY --from=iproute /tmp/output/usr /usr
RUN echo "iproute2 install" | dpkg --set-selections && \
    sed -i "/^Package: iproute2$/,/^$/ s/Status: install ok not-installed/Status: install ok installed\nVersion: $(ip -V | cut -d ',' -f2 | cut -d '-' -f 2)/" /var/lib/dpkg/status

RUN apt-get clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/* /cache

WORKDIR /

VOLUME /hosthome
VOLUME /shared
