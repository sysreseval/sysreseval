ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval

#
# DevOps image (the labs lab/sre/_DRAFT_misc/docker.py, docker-compose.py, vagrant.py and
# ansible.py): a Docker host of its own inside a lab machine, Vagrant with its docker provider, and
# an Ansible control node.
#
# The Docker hosts and the Vagrant workstation run as init machines (containerd and dockerd under a
# genuine systemd), privileged (a Docker daemon needs it):
#
#   _machine_specs = {
#        'docker1': {"privileged": True,
#                    "entrypoint": "/sbin/init",
#                    "image": sre_docker_image("devops13")},
#       .....
#   }
#
# The Ansible control node uses the image without /sbin/init, not privileged, with `'weight': 1`
# (params.image_weights counts a running Docker daemon); its managed nodes are plain init13
# machines (sshd + python3 + sudo are enough for Ansible).
#
# Docker: Docker's own repository (download.docker.com), not Debian's docker.io: docker-ce 29 with
# the containerd image store, the compose plugin, buildx; installed without the recommended
# packages.  Without access to download.docker.com, the packages dropped in cache/ (see
# cache/README).  No /etc/docker/daemon.json: the Docker labs use the defaults (a lab that wants
# other address pools writes its own file before starting the daemon, as the Vagrant lab does).
#
# AppArmor: the inner containerd and dockerd run with `container=docker` in their environment
# (drop-ins below), the docker-in-docker case of containerd's apparmor.HostSupports(): on a host
# whose kernel enforces AppArmor they neither load their docker-default profile (it would replace
# the host's, which the Kathara containers use: profiles are global to the kernel) nor apply one.
# The machine itself is privileged, hence unconfined.
#
# /var/lib/docker and /var/lib/containerd are VOLUMEs: Docker gives the container anonymous
# volumes there, directories of the host's own filesystem on which the inner daemon can use
# overlayfs (overlay2 refuses an overlayfs backing filesystem, the root of a container).  Kathara
# removes the container with its anonymous volumes (remove(v=True)), and so does `sre stop` for
# the leftovers of a lab.
#
# The lab machines have no Internet access: the Docker Hub images the labs use are shipped as
# `docker save` tarballs in /usr/local/share/sre-docker-images/ (made by `make docker-hub-images`
# of images/Makefile into cache/), loaded by /usr/local/sbin/sre-docker-load once the daemon runs.
# Docker and containerd do not start at boot: the labs start them.
#
# Vagrant: Debian 13's vagrant 2.3.7 (a git snapshot of 2023-07-31 calling itself 2.3.8.dev,
# still under the MPL: HashiCorp's later releases are under the BSL), fuse-overlayfs (the storage
# driver of last resort), zstd.  No hypervisor: Vagrant's default provider is set to docker
# (VAGRANT_DEFAULT_PROVIDER).  The box: a small Debian 13 root filesystem (debian:13-slim + sshd,
# sudo, python3, nginx, curl, iproute2...) with the user `vagrant` (sudo without password,
# Vagrant's insecure public key), stored as /usr/share/sre-vagrant/debian13-rootfs.tar.zst.  The
# lab imports it into the inner daemon (`docker import`) and adds the Vagrant box that names the
# image (a docker box: a metadata.json and a Vagrantfile).
#
# Ansible: Debian 13's ansible-core 2.19 (the engine and the ansible.builtin modules; also the
# ansible provisioner of Vagrant) and ansible 12 (the community collections: ansible.posix for
# authorized_key / sysctl, community.general...), sshpass (`ansible -k`: password login before the
# keys are installed), python3-passlib (the password_hash filter: Python 3.13 has no crypt module),
# python3-jmespath (json_query), ansible-lint and yamllint.
#
# (sre/devops13 merges the former docker13, vagrant13 and ansible13 images, 2026-11-25)
#

# --- the tools --------------------------------------------------------------------------------
FROM ${NAMESPACE}/init13:${PARENT_VERSION} AS tools
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

ENV SRE_VERSION="sre/devops13:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

# Docker's repository: its signing key must hold the fingerprint published on
# https://docs.docker.com/engine/install/debian/ (9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88).
RUN --mount=type=bind,source=cache,target=/cache \
    PACKAGES="docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"; \
    if ls /cache/docker-ce_*.deb >/dev/null 2>&1; then \
        apt-get update && apt-get install -y --no-install-recommends \
            $(for p in $PACKAGES; do ls /cache/${p}_*_$(dpkg --print-architecture).deb | sort -V | tail -1; done); \
    else \
        install -m 0755 -d /etc/apt/keyrings \
        && curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.asc \
        && mkdir -m 700 /tmp/gnupg \
        && gpg --homedir /tmp/gnupg --dry-run --quiet --no-keyring --import --import-options import-show /tmp/docker.asc \
           | grep -q 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 \
        && mv /tmp/docker.asc /etc/apt/keyrings/docker.asc && chmod a+r /etc/apt/keyrings/docker.asc \
        && rm -rf /tmp/gnupg \
        && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
           > /etc/apt/sources.list.d/docker.list \
        && apt-get update && apt-get install -y --no-install-recommends $PACKAGES; \
    fi \
    && apt-get clean && rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# Vagrant and Ansible (Debian's docker.io is not wanted: docker-ce above is the engine).
RUN apt-get update && apt-get install -y --no-install-recommends \
    vagrant \
    fuse-overlayfs \
    zstd \
    ansible \
    ansible-core \
    sshpass \
    python3-passlib \
    python3-jmespath \
    python3-argcomplete \
    ansible-lint \
    yamllint \
    && apt-get clean && rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# A bug of this Vagrant with Docker >= 24: `network_defined?` of the docker provider reads
# `IPAM.Config.size` of every network, and `docker network inspect` gives `"Config": null` for the
# `host` and `none` networks, so every `private_network` fails with "undefined method `size' for
# nil" (seen as "Error: No such object: preparing").  The same guard as its neighbour
# `network_containing_address` (fixed upstream after 2.3.7); the build fails if the line moved.
RUN f="$(dpkg -L vagrant | grep '/plugins/providers/docker/driver\.rb$')" \
    && sed -i 's/^\( *\)if (config\.size > 0 &&$/\1if (config \&\& config.size > 0 \&\&/' "$f" \
    && grep -q 'if (config && config.size > 0 &&' "$f"

# Nothing starts at boot (the labs start containerd and docker); no docker.socket activation.
RUN rm -f /etc/systemd/system/multi-user.target.wants/docker.service \
    /etc/systemd/system/multi-user.target.wants/containerd.service \
    /etc/systemd/system/sockets.target.wants/docker.socket \
    && for unit in docker containerd; do \
           mkdir -p /etc/systemd/system/$unit.service.d \
           && printf '[Service]\nEnvironment=container=docker\n' > /etc/systemd/system/$unit.service.d/sre-docker-in-docker.conf; \
       done

ENV VAGRANT_DEFAULT_PROVIDER=docker
ENV VAGRANT_CHECKPOINT_DISABLE=1
RUN printf 'export VAGRANT_DEFAULT_PROVIDER=docker\nexport VAGRANT_CHECKPOINT_DISABLE=1\n' > /etc/profile.d/vagrant.sh \
    && printf 'VAGRANT_DEFAULT_PROVIDER=docker\nVAGRANT_CHECKPOINT_DISABLE=1\n' >> /etc/environment

# Vagrant's insecure public key, for the box
RUN mkdir -p /usr/share/sre-vagrant \
    && cp "$(dpkg -L vagrant | grep '/keys/vagrant\.pub$' | head -1)" /usr/share/sre-vagrant/vagrant.pub \
    && grep -q '^ssh-' /usr/share/sre-vagrant/vagrant.pub

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

# The Docker Hub images and their loader, the box.
# (the modes set by COPY itself: a chmod in a later step would copy the 300 MB into a new layer)
COPY --chmod=0644 cache/*.tar /usr/local/share/sre-docker-images/
COPY --chmod=0755 sre-docker-load /usr/local/sbin/sre-docker-load
COPY --from=boxtar /debian13-rootfs.tar.zst /usr/share/sre-vagrant/debian13-rootfs.tar.zst
COPY check-tarballs.py /tmp/check-tarballs.py

# The tools answer, the drop-ins are there, every tarball is an image of this architecture and the
# box is a sound archive (the build fails otherwise).
RUN docker --version && dockerd --version && containerd --version && docker compose version \
    && docker buildx version \
    && grep -q '^Environment=container=docker$' /etc/systemd/system/docker.service.d/sre-docker-in-docker.conf \
    && grep -q '^Environment=container=docker$' /etc/systemd/system/containerd.service.d/sre-docker-in-docker.conf \
    && python3 /tmp/check-tarballs.py /usr/local/share/sre-docker-images "$(dpkg --print-architecture)" \
    && rm -f /tmp/check-tarballs.py \
    && vagrant --version \
    && ansible --version >/dev/null \
    && ansible-doc -t module ansible.posix.sysctl >/dev/null \
    && ansible-doc -t module ansible.posix.authorized_key >/dev/null \
    && zstd -t -q /usr/share/sre-vagrant/debian13-rootfs.tar.zst

VOLUME /var/lib/docker /var/lib/containerd
