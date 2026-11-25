ARG VERSION=latest
# version of the parent image: its own when it has one (images/Makefile), else the same as this image
ARG PARENT_VERSION=${VERSION}
ARG NAMESPACE=sysreseval
FROM ${NAMESPACE}/base13:${PARENT_VERSION}
ARG VERSION
LABEL org.opencontainers.image.authors="SysResEval"

#
# SDN image (the lab lab/sre/_DRAFT_misc/sdn.py): an OpenFlow switch and an OpenFlow controller.
# Debian 13's packages, about 55 MB on top of base13:
#
#   - openvswitch-switch (Open vSwitch 3.5: ovsdb-server, ovs-vswitchd, ovs-vsctl, ovs-ofctl,
#     ovs-appctl, ovs-dpctl) and python3-openvswitch;
#   - python3-os-ken (OS-Ken 3.0, the maintained fork of the Ryu controller: osken-manager and its
#     applications, among them os_ken.app.simple_switch_13 and the REST API os_ken.app.ofctl_rest).
#
# tshark (already in base13) decodes OpenFlow (port 6653).
#
# Open vSwitch uses the kernel datapath (the module openvswitch of the host): a container cannot
# load a module, but the kernel loads it by itself when a process asks for its generic netlink
# family (`ovs-dpctl show`), which lib/sdn.py's ovs_start_cmd() does before ovs-ctl (whose own
# `modprobe openvswitch` fails in a container but is skipped once the module is there).
#
# Nothing starts by itself: the labs start Open vSwitch with lib/sdn.py's ovs_start_cmd() and the
# controller with osken_start_cmd().
#

ENV SRE_VERSION="sre/sdn13:${VERSION}"
RUN echo "${SRE_VERSION}" >/etc/sre_version
LABEL version="${SRE_VERSION}"

ARG DEBIAN_FRONTEND="noninteractive"
RUN apt update && apt install -y --no-install-recommends \
    openvswitch-switch \
    python3-openvswitch \
    python3-os-ken

RUN rm -f /etc/systemd/system/multi-user.target.wants/openvswitch-switch.service \
          /etc/rc*.d/S*openvswitch-switch*

# OS-Ken 3 no longer ships Ryu's sample applications: simple_switch_13 (a reactive learning switch)
# and ofctl_rest (the REST northbound API, Ryu's URLs and JSON documents) written again on the
# library of OS-Ken 3 (os_ken.lib.ofctl_v1_3, os_ken.lib.hub), so that the usual command lines work:
#   osken-manager os_ken.app.simple_switch_13
#   osken-manager os_ken.app.ofctl_rest          (port 8080, OFCTL_REST_HOST / OFCTL_REST_PORT)
COPY os_ken_app/simple_switch_13.py os_ken_app/ofctl_rest.py /usr/lib/python3/dist-packages/os_ken/app/
RUN python3 -c "import os_ken.app.simple_switch_13, os_ken.app.ofctl_rest" \
    && python3 -m compileall -q /usr/lib/python3/dist-packages/os_ken/app

RUN apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

WORKDIR /
