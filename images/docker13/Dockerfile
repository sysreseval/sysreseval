ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/init13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Docker image (the labs lab/sre/_DRAFT_misc/docker.py and docker-compose.py): a Docker host of
# its own inside a lab machine.  It runs as an init machine (containerd and dockerd under a
# genuine systemd), privileged (a Docker daemon needs it):
#
#   _machine_specs = {
#        'docker1': {"privileged": True,
#                    "entrypoint": "/sbin/init",
#                    "image": sre_docker_image("docker13")},
#       .....
#   }
#
# Docker's own repository (download.docker.com), not Debian's docker.io: docker-ce 29 with the
# containerd image store, the compose plugin, buildx; installed without the recommended packages.
# Without access to download.docker.com, the packages dropped in cache/ (see cache/README).
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
# removes the container with its anonymous volumes (remove(v=True)).
#
# The lab machines have no Internet access: the Docker Hub images the labs use are shipped as
# `docker save` tarballs in /usr/local/share/sre-docker-images/ (made by `make docker-hub-images`
# of images/Makefile into cache/), loaded by /usr/local/sbin/sre-docker-load once the daemon runs.
# Docker and containerd do not start at boot: the labs start them.
#

ENV SRE_VERSION="sre/docker13:${VERSION}"
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

# Nothing starts at boot (the labs start containerd and docker); no docker.socket activation.
RUN rm -f /etc/systemd/system/multi-user.target.wants/docker.service \
    /etc/systemd/system/multi-user.target.wants/containerd.service \
    /etc/systemd/system/sockets.target.wants/docker.socket \
    && for unit in docker containerd; do \
           mkdir -p /etc/systemd/system/$unit.service.d \
           && printf '[Service]\nEnvironment=container=docker\n' > /etc/systemd/system/$unit.service.d/sre-docker-in-docker.conf; \
       done

# The Docker Hub images and their loader.
# (the modes set by COPY itself: a chmod in a later step would copy the 300 MB into a new layer)
COPY --chmod=0644 cache/*.tar /usr/local/share/sre-docker-images/
COPY --chmod=0755 sre-docker-load /usr/local/sbin/sre-docker-load
COPY check-tarballs.py /tmp/check-tarballs.py

# The tools answer, the drop-ins are there, and every tarball is an image of this architecture
# (the build fails otherwise).
RUN docker --version && dockerd --version && containerd --version && docker compose version \
    && docker buildx version \
    && grep -q '^Environment=container=docker$' /etc/systemd/system/docker.service.d/sre-docker-in-docker.conf \
    && grep -q '^Environment=container=docker$' /etc/systemd/system/containerd.service.d/sre-docker-in-docker.conf \
    && python3 /tmp/check-tarballs.py /usr/local/share/sre-docker-images "$(dpkg --print-architecture)" \
    && rm -f /tmp/check-tarballs.py

VOLUME /var/lib/docker /var/lib/containerd
