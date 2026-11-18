SHELL := /bin/bash

VERSION   ?= 1.33
NAMESPACE ?= sysreseval

IMAGES := base init routing-frr ldap-mail proxy monitoring voip aaa base13 init13

.PHONY: all $(IMAGES) push $(addprefix push-,$(IMAGES)) help

all: $(IMAGES)

base:
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/base:$(VERSION) \
		base

init: base
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/init:$(VERSION) \
		init

routing-frr: base
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/routing-frr:$(VERSION) \
		routing-frr

ldap-mail: init
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/ldap-mail:$(VERSION) \
		ldap-mail

proxy: init
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/proxy:$(VERSION) \
		proxy

monitoring: init
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/monitoring:$(VERSION) \
		monitoring

# Asterisk is compiled from its sources (see voip/Dockerfile: a few minutes, and what to put in
# voip/cache/ on a build host without access to downloads.asterisk.org and GitHub).
voip: init
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/voip:$(VERSION) \
		voip

aaa: init
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/aaa:$(VERSION) \
		aaa

# Debian 13 (trixie) twins of base and init, built on debian:13 (kathara/base is still Debian 12):
# the labs move to them one by one (sre_docker_image("base13") / ("init13")).
base13:
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/base13:$(VERSION) \
		base13

init13: base13
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/init13:$(VERSION) \
		init13

PUSH_TARGETS := $(addprefix push-,$(IMAGES))

push: $(PUSH_TARGETS)

$(PUSH_TARGETS): push-%:
	docker push $(NAMESPACE)/$*:$(VERSION)

help:
	@echo "Targets:"
	@echo "  all (default)     build base + init + routing-frr + ldap-mail + proxy + monitoring + voip + aaa + base13 + init13"
	@echo "  base | init | routing-frr | ldap-mail | proxy | monitoring | voip | aaa | base13 | init13  build one image (deps included)"
	@echo "  push              push all images"
	@echo "  push-<name>       push one image"
	@echo "Variables:"
	@echo "  VERSION   = $(VERSION)"
	@echo "  NAMESPACE = $(NAMESPACE)"
