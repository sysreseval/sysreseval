SHELL := /bin/bash

VERSION   ?= 1.28
NAMESPACE ?= sysreseval

IMAGES := base init frr

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

PUSH_TARGETS := $(addprefix push-,$(IMAGES))

push: $(PUSH_TARGETS)

$(PUSH_TARGETS): push-%:
	docker push $(NAMESPACE)/$*:$(VERSION)

help:
	@echo "Targets:"
	@echo "  all (default)     build base + init + frr"
	@echo "  base | init | frr build one image (deps included)"
	@echo "  push              push all images"
	@echo "  push-<name>       push one image"
	@echo "Variables:"
	@echo "  VERSION   = $(VERSION)"
	@echo "  NAMESPACE = $(NAMESPACE)"
