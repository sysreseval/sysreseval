SHELL := /bin/bash

VERSION   ?= 1.36
NAMESPACE ?= sysreseval

# An image may have its own version: one line `VERSION_<image> := <version>` here (none by default).
# It is then tagged, built and pushed under that version, the others under VERSION, and an image
# built FROM it takes it at that version.  `make images` of the top-level Makefile copies VERSION and
# these lines into src/SRE/params.py (default_docker_image_version, docker_image_versions).
# Meant for the images nothing is built from: the tag of an image says nothing of its parent, so
# - a new version of base13 / init13 / base12 alone changes the images built from it under their
#   unchanged tag (give them a new version too, or raise VERSION);
# - when VERSION is raised, remove these lines (or raise them): an image that keeps its own version
#   is built again on the new version of its parent, under its old tag.
# VERSION_identity13 := 1.35
# proxy13 1.37: Squid, squidclient, squidGuard, ldap-utils and duktape for the forward proxy lab, after 1.36 was published
VERSION_proxy13 := 1.37

IMAGES := base13 init13 netdev13 identity13 proxy13 monitoring13 voip13 scan13 nsm13 devops13 base12 init12

.PHONY: all $(IMAGES) push $(addprefix push-,$(IMAGES)) help docker-hub-images

all: $(IMAGES)

# $(call version,<image>): the version of an image, its own when it has one, else VERSION
version = $(or $(VERSION_$(1)),$(VERSION))

# The recipe of a rule `<image>: <parent>`: the image is built at its version, FROM its parent at
# the version of the parent (PARENT_VERSION; base13 and base12 have no parent image of ours).
# NAMESPACE names the image built and the one it is built FROM (a test build under another
# namespace never takes a parent from, nor replaces an image of, the published one).
BUILD = docker build --build-arg VERSION=$(call version,$@) --build-arg NAMESPACE=$(NAMESPACE) \
	$(if $<,--build-arg PARENT_VERSION=$(call version,$<)) -t $(NAMESPACE)/$@:$(call version,$@) $@

# Debian 13 (trixie) images, those of the labs: base13 on debian:13 (kathara/base is still
# Debian 12), init13 = base13 + a genuine systemd.
base13:
	$(BUILD)

init13: base13
	$(BUILD)

# The network devices without systemd: FRR, the multicast tools, lldpd, stayrtr, Open vSwitch +
# OS-Ken (with the applications simple_switch_13 and ofctl_rest written again for it, see
# netdev13/Dockerfile) and chrony (always -x: the NTP lab's machines must not be privileged, a
# privileged container may change the clock of the host).
netdev13: base13
	$(BUILD)

# Directory, authentication and mail: the LDAP clients, Postfix / Dovecot / OpenDKIM, FreeRADIUS,
# hostapd / wpa_supplicant, the MIT Kerberos KDC and the PAM modules.
identity13: init13
	$(BUILD)

proxy13: init13
	$(BUILD)

monitoring13: init13
	$(BUILD)

# Asterisk is compiled from its sources (see voip13/Dockerfile: a few minutes, and what to put in
# voip13/cache/ on a build host without access to downloads.asterisk.org and GitHub).
voip13: init13
	$(BUILD)

# The legacy services of the scanning and hardening lab (vsftpd, telnetd under inetd, snmpd, Redis,
# tftpd-hpa) and ndiff, on init13: its hardening targets run them under systemd.
scan13: init13
	$(BUILD)

# The network security monitoring lab: Zeek 9.0 LTS (zeek-9.0-core + zeekctl-9.0 from upstream's OBS
# repository, under /opt/zeek) and the Cowrie honeypot (3.1.8 from PyPI in a virtual environment,
# run by the user cowrie from /opt/cowrie, unit not enabled), on init13; nsm13/cache/ holds the .deb
# and the wheels for a build host without access to download.opensuse.org / PyPI.
nsm13: init13
	$(BUILD)

# A Docker host inside a lab machine (the Docker and Docker Compose labs), the developer workstation
# of the Vagrant lab and the control node of the Ansible lab: docker-ce, containerd, the compose and
# buildx plugins from download.docker.com (or devops13/cache/*.deb), the Docker Hub images of
# DOCKER_HUB_IMAGES saved as tarballs (the lab machines have no Internet access), vagrant (docker
# provider) with a small Debian 13 box root filesystem built from debian:13-slim, ansible-core and
# the community collections (see devops13/Dockerfile).
devops13: init13 docker-hub-images
	$(BUILD)

# The Docker Hub images shipped in the devops13 image: one `docker save` per tag into devops13/cache/
# (<repository>_<tag>.tar), pulled through the build host's own Docker daemon (its registry mirror
# and proxy apply), for the architecture of that daemon.  A tarball already there is kept.  The
# tags are pinned: the labs name only the aliases that devops13/sre-docker-load gives them
# (nginx:alpine, python:alpine, redis:alpine, alpine, busybox, registry, hello-world).
DOCKER_HUB_IMAGES ?= hello-world:latest alpine:3.24 busybox:1.38 nginx:1.30-alpine python:3.14-alpine \
	redis:8.6-alpine registry:3
docker-hub-images:
	@arch=$$(docker version --format '{{.Server.Arch}}'); \
	for image in $(DOCKER_HUB_IMAGES); do \
		file=devops13/cache/$$(echo "$$image" | tr ':/' '_-').tar; \
		if [ -s "$$file" ]; then echo "$$file: kept"; continue; fi; \
		docker pull -q --platform linux/$$arch "$$image" \
		&& docker save --platform linux/$$arch -o "$$file.part" "$$image" \
		&& mv "$$file.part" "$$file" && echo "$$file: saved" \
		|| { rm -f "$$file.part"; exit 1; }; \
	done

# Debian 12 (bookworm) images, kept for the labs that still name them: base12 on kathara/base,
# init12 = base12 + a genuine systemd.  No other image is built from them any more.
base12:
	$(BUILD)

init12: base12
	$(BUILD)

PUSH_TARGETS := $(addprefix push-,$(IMAGES))

push: $(PUSH_TARGETS)

$(PUSH_TARGETS): push-%:
	docker push $(NAMESPACE)/$*:$(call version,$*)

help:
	@echo "Targets:"
	@echo "  all (default)     build base13 + init13 + netdev13 + identity13 + proxy13 + monitoring13 + voip13 + scan13 + nsm13 + devops13 + base12 + init12"
	@echo "  base13 | init13 | netdev13 | identity13 | proxy13 | monitoring13 | voip13 | scan13 | nsm13 | devops13 | base12 | init12  build one image (deps included)"
	@echo "  docker-hub-images the Docker Hub tarballs of the devops13 image (devops13/cache/)"
	@echo "  push              push all images"
	@echo "  push-<name>       push one image"
	@echo "Variables:"
	@echo "  VERSION   = $(VERSION)"
	@echo "  NAMESPACE = $(NAMESPACE)"
	@echo "  VERSION_<image>   the version of one image, when it is not VERSION"
	@$(foreach image,$(IMAGES),$(if $(VERSION_$(image)),echo "  VERSION_$(image) = $(VERSION_$(image))";))
