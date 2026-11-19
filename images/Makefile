SHELL := /bin/bash

VERSION   ?= 1.34
NAMESPACE ?= sysreseval

IMAGES := base13 init13 routing-frr ldap-mail proxy monitoring voip aaa base12 init12

.PHONY: all $(IMAGES) push $(addprefix push-,$(IMAGES)) help

all: $(IMAGES)

# NAMESPACE names the image built and the one it is built FROM (a test build under another
# namespace never takes a parent from, nor replaces an image of, the published one).
BUILD = docker build --build-arg VERSION=$(VERSION) --build-arg NAMESPACE=$(NAMESPACE)

# Debian 13 (trixie) images, those of the labs: base13 on debian:13 (kathara/base is still
# Debian 12), init13 = base13 + a genuine systemd.
base13:
	$(BUILD) -t $(NAMESPACE)/base13:$(VERSION) base13

init13: base13
	$(BUILD) -t $(NAMESPACE)/init13:$(VERSION) init13

routing-frr: base13
	$(BUILD) -t $(NAMESPACE)/routing-frr:$(VERSION) routing-frr

ldap-mail: init13
	$(BUILD) -t $(NAMESPACE)/ldap-mail:$(VERSION) ldap-mail

proxy: init13
	$(BUILD) -t $(NAMESPACE)/proxy:$(VERSION) proxy

monitoring: init13
	$(BUILD) -t $(NAMESPACE)/monitoring:$(VERSION) monitoring

# Asterisk is compiled from its sources (see voip/Dockerfile: a few minutes, and what to put in
# voip/cache/ on a build host without access to downloads.asterisk.org and GitHub).
voip: init13
	$(BUILD) -t $(NAMESPACE)/voip:$(VERSION) voip

aaa: init13
	$(BUILD) -t $(NAMESPACE)/aaa:$(VERSION) aaa

# Debian 12 (bookworm) images, kept for the labs that still name them: base12 on kathara/base,
# init12 = base12 + a genuine systemd.  No other image is built from them any more.
base12:
	$(BUILD) -t $(NAMESPACE)/base12:$(VERSION) base12

init12: base12
	$(BUILD) -t $(NAMESPACE)/init12:$(VERSION) init12

PUSH_TARGETS := $(addprefix push-,$(IMAGES))

push: $(PUSH_TARGETS)

$(PUSH_TARGETS): push-%:
	docker push $(NAMESPACE)/$*:$(VERSION)

help:
	@echo "Targets:"
	@echo "  all (default)     build base13 + init13 + routing-frr + ldap-mail + proxy + monitoring + voip + aaa + base12 + init12"
	@echo "  base13 | init13 | routing-frr | ldap-mail | proxy | monitoring | voip | aaa | base12 | init12  build one image (deps included)"
	@echo "  push              push all images"
	@echo "  push-<name>       push one image"
	@echo "Variables:"
	@echo "  VERSION   = $(VERSION)"
	@echo "  NAMESPACE = $(NAMESPACE)"
