ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/init13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# Network security monitoring image (the lab lab/sre/_DRAFT_misc/nsm-forensics.py): the Zeek network
# monitor and the Cowrie SSH honeypot.  Neither is packaged by Debian 13:
#
#   - Zeek, the 9.0 LTS line of upstream's OBS repository (security:zeek, Debian_13), only the
#     packages zeek-9.0-core (zeek, zeek-cut, the scripts) and zeekctl-9.0 (no spicy-dev, btest,
#     zkg): installed under /opt/zeek, /opt/zeek/bin added to the PATH.  About 66 MB installed
#     (libmaxminddb0, libzmq5 with it).  The repository key is checked by its fingerprint.
#   - Cowrie 3.1.8 from PyPI, in a virtual environment /opt/cowrie/cowrie-env (its dependencies
#     are pinned with ==: Debian's python3-* packages cannot be used), run by the user `cowrie`
#     (Cowrie refuses root) from its state directory /opt/cowrie, prepared by `cowrie init`
#     (etc/cowrie.cfg = the bundled defaults, var/log/cowrie, var/lib/cowrie...).  A unit
#     cowrie.service is installed, not enabled (the lab's students enable it).
#
# Without access to download.opensuse.org or PyPI, the files dropped in cache/ are used (see
# cache/README): the two .deb of Zeek and the wheels of Cowrie and of its dependencies.
#
# The honeypot runs as an init machine (Cowrie and the real sshd under a genuine systemd); the
# sensor and the analyst's workstation use the image without /sbin/init:
#
#   _machine_specs = {
#        'honeypot': {"privileged": True,
#                     "entrypoint": "/sbin/init",
#                     "image": sre_docker_image("nsm13")},
#        'sensor': {"image": sre_docker_image("nsm13")},
#       .....
#   }
#

ENV SRE_VERSION="sre/nsm13:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"
ARG ZEEK_LINE=9.0
ARG ZEEK_REPO=https://download.opensuse.org/repositories/security:/zeek/Debian_13/
ARG ZEEK_SIGNER_FPR=F9FA0223B56B116C363737EF5DA57BDD6DD785CA
ARG COWRIE_VERSION=3.1.8

COPY cache/ /cache/

# Zeek (the cached .deb when present, else the OBS repository), python3-venv for Cowrie and xxd (to decode
# the hexadecimal of a capture: not in base13); the apt
# lists and caches are removed in the same step (a later step would leave them in this layer)
RUN arch=$(dpkg --print-architecture) \
 && apt-get update \
 && if ls /cache/zeek-${ZEEK_LINE}-core_*_${arch}.deb /cache/zeekctl-${ZEEK_LINE}_*_${arch}.deb >/dev/null 2>&1; then \
        apt-get install -y --no-install-recommends python3-venv xxd \
            "$(ls /cache/zeek-${ZEEK_LINE}-core_*_${arch}.deb | sort -V | tail -1)" \
            "$(ls /cache/zeekctl-${ZEEK_LINE}_*_${arch}.deb | sort -V | tail -1)"; \
    else \
        curl -fsSL "${ZEEK_REPO}Release.key" -o /tmp/zeek.key \
        && mkdir -m 700 /tmp/gnupg \
        && gpg --homedir /tmp/gnupg --dry-run --quiet --no-keyring --import --import-options import-show /tmp/zeek.key \
           | grep -q "${ZEEK_SIGNER_FPR}" \
        && gpg --homedir /tmp/gnupg --dearmor < /tmp/zeek.key > /usr/share/keyrings/zeek-archive-keyring.gpg \
        && rm -rf /tmp/gnupg /tmp/zeek.key \
        && echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] ${ZEEK_REPO} /" \
           > /etc/apt/sources.list.d/zeek.list \
        && apt-get update \
        && apt-get install -y --no-install-recommends python3-venv xxd zeek-${ZEEK_LINE}-core zeekctl-${ZEEK_LINE}; \
    fi \
 && apt-get clean \
 && rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/* \
 && /opt/zeek/bin/zeek --version \
 && test -x /opt/zeek/bin/zeek-cut \
 && test -x /opt/zeek/bin/zeekctl

ENV PATH="/opt/zeek/bin:${PATH}"
RUN printf '%s\n' 'case ":$PATH:" in *:/opt/zeek/bin:*) ;; *) PATH="/opt/zeek/bin:$PATH" ;; esac' \
        > /etc/profile.d/zeek.sh

# Cowrie: the user, the virtual environment (the cached wheels when present, else PyPI), the state
# directory prepared by `cowrie init`, the bundled defaults beside it for reference
RUN useradd --system --home-dir /opt/cowrie --create-home --shell /usr/sbin/nologin cowrie \
 && python3 -m venv /opt/cowrie/cowrie-env \
 && if ls /cache/wheels/cowrie-${COWRIE_VERSION}-*.whl >/dev/null 2>&1; then \
        /opt/cowrie/cowrie-env/bin/pip install --no-cache-dir --no-index --find-links /cache/wheels "cowrie==${COWRIE_VERSION}"; \
    else \
        /opt/cowrie/cowrie-env/bin/pip install --no-cache-dir "cowrie==${COWRIE_VERSION}"; \
    fi \
 && cd /opt/cowrie && runuser -u cowrie -- /opt/cowrie/cowrie-env/bin/cowrie init \
 && cp etc/cowrie.cfg etc/cowrie.cfg.dist \
 && cp "$(/opt/cowrie/cowrie-env/bin/python3 -c 'import cowrie.data, os; print(os.path.dirname(cowrie.data.__file__))')/etc/userdb.example" \
       etc/userdb.example \
 && chown -R cowrie:cowrie /opt/cowrie \
 && rm -rf /cache /root/.cache

# The unit (not enabled): `cowrie start` runs twistd, found on the PATH (the virtual environment is not
# activated); `-- -n` hands -n (foreground) to twistd, which keeps its pid file and cowrie.log (Cowrie's
# own -n is refused by its argument parser); cowrie.log and cowrie.json under /opt/cowrie/var/log/cowrie
RUN printf '%s\n' '[Unit]' 'Description=Cowrie SSH and Telnet honeypot' 'After=network-online.target' '' \
        '[Service]' 'Type=simple' 'User=cowrie' 'Group=cowrie' 'WorkingDirectory=/opt/cowrie' \
        'Environment=PATH=/opt/cowrie/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin' \
        'ExecStart=/opt/cowrie/cowrie-env/bin/cowrie start -- -n' 'Restart=on-failure' 'RestartSec=5' '' \
        '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/cowrie.service \
 && systemctl enable cowrie >/dev/null 2>&1 \
 && systemctl disable cowrie >/dev/null 2>&1 \
 && test ! -e /etc/systemd/system/multi-user.target.wants/cowrie.service

WORKDIR /

VOLUME /hosthome
VOLUME /shared
