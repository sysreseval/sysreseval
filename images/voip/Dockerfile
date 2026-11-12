ARG VERSION=latest

# ---------------------------------------------------------------------------
# Stage 1: Asterisk compiled from the upstream tarball.  Debian 12 and 13 have no asterisk
# package (bullseye has 16.28, the next one is in forky / sid), so the 22 LTS line is built
# here: bundled pjproject (the SIP stack of chan_pjsip), SRTP, TLS, voicemail, the English and
# French core sounds in A-law.  BUILD_NATIVE is off: the image must run on every CPU of the pool.
#
# The build downloads three things: the Asterisk tarball (checked against the pinned sha256),
# pjproject (GitHub, checked against the md5 of the Asterisk tree) and the sounds
# (downloads.asterisk.org, checked against their .sha1).  A build host that cannot reach those
# sites takes them from cache/ instead, where they are dropped by hand before the build:
#
#   cache/asterisk-22.12.0.tar.gz
#   cache/pjproject-2.17.tar.bz2
#   cache/asterisk-core-sounds-{en,fr}-alaw-1.6.1.tar.gz  and their  .tar.gz.sha1
# ---------------------------------------------------------------------------
FROM debian:12 AS build

ARG ASTERISK_VERSION=22.12.0
ARG ASTERISK_SHA256=f8b2ba98aac6c4ff3376bc0a2868bea6ed577ca684efb7ec739ae6e8ce6e35e2
ARG ASTERISK_URL=https://downloads.asterisk.org/pub/telephony/asterisk/releases
ARG DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    bzip2 \
    patch \
    wget \
    ca-certificates \
    file \
    libedit-dev \
    libjansson-dev \
    libsqlite3-dev \
    uuid-dev \
    libxml2-dev \
    libssl-dev \
    libsrtp2-dev \
    libsystemd-dev \
    zlib1g-dev

COPY cache/ /cache/

WORKDIR /usr/src
RUN test -f /cache/asterisk-${ASTERISK_VERSION}.tar.gz \
     || wget -nv -O /cache/asterisk-${ASTERISK_VERSION}.tar.gz ${ASTERISK_URL}/asterisk-${ASTERISK_VERSION}.tar.gz; \
    echo "${ASTERISK_SHA256}  /cache/asterisk-${ASTERISK_VERSION}.tar.gz" | sha256sum -c - \
 && tar -xzf /cache/asterisk-${ASTERISK_VERSION}.tar.gz

WORKDIR /usr/src/asterisk-${ASTERISK_VERSION}
RUN ./configure --with-pjproject-bundled --with-externals-cache=/cache --with-sounds-cache=/cache \
 && make menuselect.makeopts \
 && menuselect/menuselect \
        --disable BUILD_NATIVE \
        --disable-category MENUSELECT_MOH \
        --disable CORE-SOUNDS-EN-GSM \
        --enable CORE-SOUNDS-EN-ALAW \
        --enable CORE-SOUNDS-FR-ALAW \
        menuselect.makeopts \
 && make -j"$(nproc)" \
 && make install DESTDIR=/out

# No debugging symbols in the image; /var/run is a link to /run in the final image (the unit and
# Asterisk itself create the run directory).
RUN find /out -type f \( -name '*.so' -o -name '*.so.*' -o -path '*/sbin/asterisk' \) -exec strip --strip-unneeded {} + \
 && rm -rf /out/var/run /out/usr/include


# ---------------------------------------------------------------------------
# Stage 2: the image of the labs
# ---------------------------------------------------------------------------
FROM sysreseval/init:${VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# VoIP image (the SIP / RTP lab): Asterisk 22 (chan_pjsip, voicemail, SRTP, TLS; stage 1) and the
# SIP tools baresip (a console softphone: with the sine source and the sndfile recorder it needs
# no sound card), sngrep (SIP call flows on a terminal), sipsak (OPTIONS / REGISTER tests) and
# sox (wav files), on top of the init image so that the PBX runs under a genuine systemd
# (systemctl restart asterisk, journalctl).  tcpdump, tshark and Wireshark come from the base
# image.  Declare the PBX like the init machines:
#
#   _machine_specs = {
#        'pbx': {"privileged": True,
#                "entrypoint": "/sbin/init",
#                "image": sre_docker_image("voip")},
#       .....
#   }
#
# A softphone machine uses the image without /sbin/init (then only baresip / sngrep matter); a
# PBX without systemd is started with `asterisk` (it goes to the background by itself) and
# awaited with `asterisk -rx "core waitfullybooted"`.
#
# /etc/asterisk holds a minimal configuration (no account, no dialplan): the labs write
# pjsip.conf, extensions.conf, rtp.conf and voicemail.conf.  Asterisk runs as root.
#

ENV SRE_VERSION="sre/voip:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

RUN apt update && apt install -y \
    libedit2 \
    libjansson4 \
    libsqlite3-0 \
    libuuid1 \
    libxml2 \
    libssl3 \
    libsrtp2-1 \
    libsystemd0 \
    baresip-core \
    sngrep \
    sipsak \
    sox

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

COPY --from=build /out/ /
COPY etc-asterisk/ /etc/asterisk/
# Like the other services of the init image: installed, never started by itself.
COPY asterisk.service /lib/systemd/system/asterisk.service
# baresip needs $LOGNAME to find ~/.baresip: a wrapper ahead of /usr/bin in the PATH sets it.
COPY baresip /usr/local/bin/baresip
RUN chmod 755 /usr/local/bin/baresip && ldconfig

WORKDIR /

VOLUME /hosthome
VOLUME /shared
