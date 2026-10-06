SHELL := /bin/bash

VERSION   ?= 1.30
NAMESPACE ?= sysreseval

IMAGES := base init frr mail

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

mail: init
	docker build --build-arg VERSION=$(VERSION) \
		-t $(NAMESPACE)/mail:$(VERSION) \
		mail

PUSH_TARGETS := $(addprefix push-,$(IMAGES))

push: $(PUSH_TARGETS)

$(PUSH_TARGETS): push-%:
	docker push $(NAMESPACE)/$*:$(VERSION)

help:
	@echo "Targets:"
	@echo "  all (default)     build base + init + frr + mail"
	@echo "  base | init | frr | mail  build one image (deps included)"
	@echo "  push              push all images"
	@echo "  push-<name>       push one image"
	@echo "Variables:"
	@echo "  VERSION   = $(VERSION)"
	@echo "  NAMESPACE = $(NAMESPACE)"
