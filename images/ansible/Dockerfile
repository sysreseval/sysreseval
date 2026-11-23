ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/base13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Ansible image (the Ansible automation lab): the control node only.  The managed nodes of the
# lab are plain init13 machines (sshd + python3 + sudo are enough for Ansible); nothing runs here
# but the students' ansible / ansible-playbook commands, so the image needs no systemd:
#
#   _machine_specs = {
#        'control': {"image": sre_docker_image("ansible")},
#       .....
#   }
#
# Debian 13 packages: ansible-core 2.19 (the engine and the ansible.builtin modules) and ansible 12
# (the community collections: ansible.posix for authorized_key / sysctl, community.general...),
# sshpass (`ansible -k`: password login before the keys are installed), python3-passlib (the
# password_hash filter: Python 3.13 has no crypt module), python3-jmespath (json_query),
# ansible-lint and yamllint.
#

ENV SRE_VERSION="sre/ansible:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"

RUN apt update && apt install -y --no-install-recommends \
    ansible \
    ansible-core \
    sshpass \
    python3-passlib \
    python3-jmespath \
    python3-argcomplete \
    ansible-lint \
    yamllint

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

# The engine and the collections answer (the build fails on a broken installation).
RUN ansible --version && ansible-doc -t module ansible.posix.sysctl >/dev/null \
    && ansible-doc -t module ansible.posix.authorized_key >/dev/null
