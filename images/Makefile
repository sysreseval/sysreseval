SHELL := /bin/bash

VERSION   ?= 1.35
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
# VERSION_ldap-mail := 1.35

IMAGES := base13 init13 routing-frr ldap-mail proxy monitoring voip aaa ansible ntp base12 init12

.PHONY: all $(IMAGES) push $(addprefix push-,$(IMAGES)) help

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

routing-frr: base13
	$(BUILD)

ldap-mail: init13
	$(BUILD)

proxy: init13
	$(BUILD)

monitoring: init13
	$(BUILD)

# Asterisk is compiled from its sources (see voip/Dockerfile: a few minutes, and what to put in
# voip/cache/ on a build host without access to downloads.asterisk.org and GitHub).
voip: init13
	$(BUILD)

aaa: init13
	$(BUILD)

# The control node of the Ansible lab (ansible-core + the community collections); its managed
# nodes are init13 machines.
ansible: base13
	$(BUILD)

# chrony on base13, without systemd: the NTP lab's machines must not be privileged (see
# ntp/Dockerfile: a privileged container may change the clock of the host).
ntp: base13
	$(BUILD)

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
	@echo "  all (default)     build base13 + init13 + routing-frr + ldap-mail + proxy + monitoring + voip + aaa + ansible + ntp + base12 + init12"
	@echo "  base13 | init13 | routing-frr | ldap-mail | proxy | monitoring | voip | aaa | ansible | ntp | base12 | init12  build one image (deps included)"
	@echo "  push              push all images"
	@echo "  push-<name>       push one image"
	@echo "Variables:"
	@echo "  VERSION   = $(VERSION)"
	@echo "  NAMESPACE = $(NAMESPACE)"
	@echo "  VERSION_<image>   the version of one image, when it is not VERSION"
	@$(foreach image,$(IMAGES),$(if $(VERSION_$(image)),echo "  VERSION_$(image) = $(VERSION_$(image))";))
