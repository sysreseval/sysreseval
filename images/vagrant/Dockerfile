ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval

#
# Vagrant image (the Vagrant lab lab/sre/_DRAFT_misc/vagrant.py): a developer workstation where
# Vagrant creates its guests with the docker provider, in a Docker daemon of its own.  It runs as an
# init machine (dockerd and containerd under a genuine systemd), privileged (a Docker daemon needs
# it):
#
#   _machine_specs = {
#        'dev': {"privileged": True,
#                "entrypoint": "/sbin/init",
#                "image": sre_docker_image("vagrant")},
#       .....
#   }
#
# Debian 13 packages: vagrant 2.3.7 (a git snapshot of 2023-07-31 calling itself 2.3.8.dev, still
# under the MPL: HashiCorp's later releases are under the BSL), docker.io 26 (dockerd, containerd,
# runc) and docker-cli (only recommended by docker.io), fuse-overlayfs (the
# storage driver of last resort), ansible-core (the ansible provisioner of Vagrant), zstd.
# No hypervisor: Vagrant's default provider is set to docker (VAGRANT_DEFAULT_PROVIDER).
#
# /var/lib/docker is a VOLUME: Docker gives the container an anonymous volume there, a directory
# of the host's own filesystem, on which the inner daemon uses overlay2 (overlay2 refuses an
# overlayfs backing filesystem, the root of a container).  Kathara removes the container with its
# anonymous volumes (remove(v=True)), and so does `sre stop` for the leftovers of a lab.
#
# The box: a small Debian 13 root filesystem (debian:13-slim + sshd, sudo, python3, nginx, curl,
# iproute2...) with the user `vagrant` (sudo without password, Vagrant's insecure public key),
# stored as /usr/share/sre-vagrant/debian13-rootfs.tar.zst.  The lab imports it into the inner
# daemon (`docker import`) and adds the Vagrant box that names the image (a docker box: a
# metadata.json and a Vagrantfile).  Docker and containerd do not start at boot: the lab starts
# them.
#

# --- the workstation's tools ------------------------------------------------------------------
FROM ${NAMESPACE}/init13:${PARENT_VERSION} AS tools
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

ENV SRE_VERSION="sre/vagrant:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && apt-get install -y --no-install-recommends \
    vagrant \
    docker.io \
    docker-cli \
    fuse-overlayfs \
    ansible-core \
    zstd \
    && apt-get clean && rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# A bug of this Vagrant with Docker >= 24: `network_defined?` of the docker provider reads
# `IPAM.Config.size` of every network, and `docker network inspect` gives `"Config": null` for the
# `host` and `none` networks, so every `private_network` fails with "undefined method `size' for
# nil" (seen as "Error: No such object: preparing").  The same guard as its neighbour
# `network_containing_address` (fixed upstream after 2.3.7); the build fails if the line moved.
RUN f="$(dpkg -L vagrant | grep '/plugins/providers/docker/driver\.rb$')" \
    && sed -i 's/^\( *\)if (config\.size > 0 &&$/\1if (config \&\& config.size > 0 \&\&/' "$f" \
    && grep -q 'if (config && config.size > 0 &&' "$f"

# Nothing starts at boot (the lab starts docker); no docker.socket activation either.
RUN rm -f /etc/systemd/system/multi-user.target.wants/docker.service \
    /etc/systemd/system/multi-user.target.wants/containerd.service \
    /etc/systemd/system/sockets.target.wants/docker.socket

# The inner daemon: its default bridge and the pool of its networks (Vagrant's private networks
# of the lab are 192.168.x.0/24, the lab networks are drawn outside these ranges); small logs.
RUN mkdir -p /etc/docker && printf '%s\n' \
    '{' \
    '  "bip": "10.250.0.1/24",' \
    '  "default-address-pools": [{"base": "10.251.0.0/16", "size": 24}],' \
    '  "log-driver": "json-file",' \
    '  "log-opts": {"max-size": "1m", "max-file": "2"}' \
    '}' > /etc/docker/daemon.json

ENV VAGRANT_DEFAULT_PROVIDER=docker
ENV VAGRANT_CHECKPOINT_DISABLE=1
RUN printf 'export VAGRANT_DEFAULT_PROVIDER=docker\nexport VAGRANT_CHECKPOINT_DISABLE=1\n' > /etc/profile.d/vagrant.sh \
    && printf 'VAGRANT_DEFAULT_PROVIDER=docker\nVAGRANT_CHECKPOINT_DISABLE=1\n' >> /etc/environment

# Vagrant's insecure public key, for the box
RUN mkdir -p /usr/share/sre-vagrant \
    && cp "$(dpkg -L vagrant | grep '/keys/vagrant\.pub$' | head -1)" /usr/share/sre-vagrant/vagrant.pub \
    && grep -q '^ssh-' /usr/share/sre-vagrant/vagrant.pub

VOLUME /var/lib/docker

# --- the box ----------------------------------------------------------------------------------
FROM debian:13-slim AS box
ARG DEBIAN_FRONTEND="noninteractive"
COPY --from=tools /usr/share/sre-vagrant/vagrant.pub /tmp/vagrant.pub
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    python3 \
    nginx \
    curl \
    ca-certificates \
    iproute2 \
    iputils-ping \
    procps \
    netcat-openbsd \
    less \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin \
    && useradd -m -s /bin/bash vagrant \
    && echo 'vagrant:vagrant' | chpasswd \
    && printf 'vagrant ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/vagrant && chmod 0440 /etc/sudoers.d/vagrant \
    && visudo -c \
    && install -d -m 700 -o vagrant -g vagrant /home/vagrant/.ssh \
    && install -m 600 -o vagrant -g vagrant /tmp/vagrant.pub /home/vagrant/.ssh/authorized_keys \
    && rm -f /tmp/vagrant.pub /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd \
    && printf 'UseDNS no\n' > /etc/ssh/sshd_config.d/vagrant.conf \
    && rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/info/* /tmp/* /var/tmp/*

# --- the box as a tarball -----------------------------------------------------------------------
FROM debian:13-slim AS boxtar
COPY --from=box / /rootfs/
RUN apt-get update && apt-get install -y --no-install-recommends zstd \
    && tar -C /rootfs --numeric-owner -cf - . | zstd -19 -T0 -q -o /debian13-rootfs.tar.zst

# --- the image ----------------------------------------------------------------------------------
FROM tools
COPY --from=boxtar /debian13-rootfs.tar.zst /usr/share/sre-vagrant/debian13-rootfs.tar.zst

# The tools answer (the build fails on a broken installation).
RUN vagrant --version && docker --version && dockerd --version && ansible --version >/dev/null \
    && zstd -t -q /usr/share/sre-vagrant/debian13-rootfs.tar.zst
