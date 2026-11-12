SHELL := /bin/bash

VERSION   ?= 1.33
NAMESPACE ?= sysreseval

IMAGES := base init frr ldap-mail proxy monitoring voip

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

frr: base
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/frr:$(VERSION) \
		frr

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

PUSH_TARGETS := $(addprefix push-,$(IMAGES))

push: $(PUSH_TARGETS)

$(PUSH_TARGETS): push-%:
	docker push $(NAMESPACE)/$*:$(VERSION)

help:
	@echo "Targets:"
	@echo "  all (default)     build base + init + frr + ldap-mail + proxy + monitoring + voip"
	@echo "  base | init | frr | ldap-mail | proxy | monitoring | voip  build one image (deps included)"
	@echo "  push              push all images"
	@echo "  push-<name>       push one image"
	@echo "Variables:"
	@echo "  VERSION   = $(VERSION)"
	@echo "  NAMESPACE = $(NAMESPACE)"
