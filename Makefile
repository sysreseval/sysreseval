
SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: venv fonts network-plugin translations wrappers sre-wrapper install check-debug-mode tests test functional-tests exam-tests all-tests set-debug-mode remove-debug-mode docs api_doc main_docs main_doc_pdf main_doc_html images

IMAGES_VERSION := $(shell awk '/^VERSION[[:space:]]*\??=/ {print $$NF; exit}' $(ROOT_DIR)/images/Makefile)

# DejaVu fonts embedded in the PDFs of "sre export" and "sre outline" (params.pdf_font_files).
DEJAVU_VERSION := 2.37
DEJAVU_URL := https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_$(subst .,_,$(DEJAVU_VERSION))/dejavu-fonts-ttf-$(DEJAVU_VERSION).tar.bz2
DEJAVU_SHA256 := fa9ca4d13871dd122f61258a80d01751d603b4d3ee14095d65453b4e846e17d7
DEJAVU_FILES := DejaVuSans.ttf DejaVuSans-Bold.ttf DejaVuSans-Oblique.ttf DejaVuSans-BoldOblique.ttf DejaVuSansMono.ttf DejaVuSansMono-Bold.ttf
FONT_DIR := ${ROOT_DIR}/graphics/fonts

# Kathara network plugin (VDE) with the types of switch: `mode` 'switch' / 'managed' of a network.
# Built from the fork and installed under the name Kathara looks for, in place of the stock plugin.
NETWORK_PLUGIN_REPO ?= https://github.com/emotchane/NetworkPlugin.git
NETWORK_PLUGIN_BRANCH ?= main
NETWORK_PLUGIN_NAME ?= kathara/katharanp_vde
# Published build of that plugin (Docker Hub): downloaded when it exists, so that nothing is compiled
NETWORK_PLUGIN_IMAGE ?= sysreseval/katharanp_vde
NETWORK_PLUGIN_MODES_ENV := KATHARA_SWITCH_MODES
NETWORK_PLUGIN_DIR := ${ROOT_DIR}/build/NetworkPlugin

# Minimal pkg_resources stub. The 'fs' library (a Kathara dependency) calls
# pkg_resources.declare_namespace at import time, so we cannot simply uninstall
# pkg_resources.
define PKG_RESOURCES_STUB
def declare_namespace(name): pass

def iter_entry_points(group, name=None):
    from importlib.metadata import entry_points
    eps = entry_points(group=group)
    return iter(ep for ep in eps if name is None or ep.name == name)

def register_loader_type(loader_type, provider_factory):
    pass

def register_finder(importer_type, distribution_finder):
    pass

def find_on_path(*args, **kwargs):
    return iter(())

def get_provider(moduleOrReq):
    return None
endef
export PKG_RESOURCES_STUB

docs: api_doc main_doc_pdf main_doc_html

main_docs: main_doc_pdf main_doc_html

main_doc_pdf:
	${ROOT_DIR}/venv/bin/pip install --quiet sphinx myst-parser furo
	${ROOT_DIR}/venv/bin/sphinx-build -M latexpdf \
		${ROOT_DIR}/docs/sphinx \
		${ROOT_DIR}/docs/sphinx/_build
	cp ${ROOT_DIR}/docs/sphinx/_build/latex/sre.pdf ${ROOT_DIR}/docs/documentation.pdf
	@echo "PDF written to ${ROOT_DIR}/docs/documentation.pdf"

main_doc_html:
	${ROOT_DIR}/venv/bin/pip install --quiet sphinx myst-parser furo
	${ROOT_DIR}/venv/bin/sphinx-build -a -E -b html \
		${ROOT_DIR}/docs/sphinx \
		${ROOT_DIR}/docs/html/main
	@echo "HTML written to ${ROOT_DIR}/docs/html/main/"

api_doc:
	${ROOT_DIR}/venv/bin/pip install --quiet pdoc
	@# Create minimal Kathara stubs so pdoc never loads the real package (which pulls in
	@# the 'fs' library that requires pkg_resources and fails outside a full install).
	@${ROOT_DIR}/venv/bin/python3 -c "\
	import os; \
	base='/tmp/_pdoc_stubs'; \
	[os.makedirs(f'{base}/{d}', exist_ok=True) for d in ['Kathara/manager','Kathara/model']]; \
	[open(f'{base}/{f}','w').write(c) for f,c in [\
	  ('Kathara/__init__.py',''),\
	  ('Kathara/manager/__init__.py',''),\
	  ('Kathara/manager/Kathara.py','class Kathara: pass\n'),\
	  ('Kathara/model/__init__.py',''),\
	  ('Kathara/model/Lab.py','class Lab: pass\n'),\
	]]"
	PYTHONPATH=/tmp/_pdoc_stubs:${ROOT_DIR}/src:${ROOT_DIR}:${ROOT_DIR}/lib \
	${ROOT_DIR}/venv/bin/pdoc \
		--output-dir ${ROOT_DIR}/docs/html/api \
		--docformat google \
		SRE.lib_sre SRE.common SRE.params \
		lib.ips lib.net_config lib.dhcp lib.tls lib.grade_helpers lib.frr lib.state_helpers lib.switch lib.utils
	@echo "Docs written to ${ROOT_DIR}/docs/html/api"

# Download the DejaVu fonts into graphics/fonts (nothing to do when they are already there).
# Without them the PDFs fall back on the core fonts and their text is reduced to Latin-1.
fonts:
	@set -e; \
	missing=0; for f in $(DEJAVU_FILES); do [ -s "$(FONT_DIR)/$$f" ] || missing=1; done; \
	if [ $$missing -eq 0 ]; then echo "DejaVu fonts already in $(FONT_DIR)"; exit 0; fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	echo "Downloading DejaVu $(DEJAVU_VERSION) fonts"; \
	curl -fsSL -o "$$tmp/dejavu.tar.bz2" "$(DEJAVU_URL)"; \
	if command -v sha256sum >/dev/null 2>&1; then sum=$$(sha256sum "$$tmp/dejavu.tar.bz2"); \
	else sum=$$(shasum -a 256 "$$tmp/dejavu.tar.bz2"); fi; \
	[ "$${sum%% *}" = "$(DEJAVU_SHA256)" ] \
		|| { echo "ERROR: unexpected SHA-256 for $(DEJAVU_URL): $${sum%% *}"; exit 1; }; \
	tar -xjf "$$tmp/dejavu.tar.bz2" -C "$$tmp"; \
	mkdir -p "$(FONT_DIR)"; \
	for f in $(DEJAVU_FILES); do \
		install -m 644 "$$tmp/dejavu-fonts-ttf-$(DEJAVU_VERSION)/ttf/$$f" "$(FONT_DIR)/$$f"; \
	done; \
	install -m 644 "$$tmp/dejavu-fonts-ttf-$(DEJAVU_VERSION)/LICENSE" "$(FONT_DIR)/LICENSE"; \
	echo "DejaVu fonts installed in $(FONT_DIR)"

# Install the network plugin that knows the switch types (run as root or as a member of the
# docker group): downloaded from $(NETWORK_PLUGIN_IMAGE) when it is published there, built from the
# sources otherwise or with BUILD=1 (needs docker with buildx, git and python3).  Does nothing
# when the installed plugin already has the switch types (FORCE=1 installs it again); refuses
# while a Kathara network exists, since the stock plugin is removed first.
network-plugin:
	@set -e; \
	case "$$(uname -m)" in \
		x86_64) arch=amd64;; \
		aarch64|arm64) arch=arm64;; \
		*) echo "ERROR: unsupported architecture $$(uname -m)"; exit 1;; \
	esac; \
	plugin="$(NETWORK_PLUGIN_NAME):$$arch"; \
	docker info >/dev/null 2>&1 || { echo "ERROR: the Docker daemon is not reachable"; exit 1; }; \
	has_modes() { docker plugin inspect "$$plugin" --format '{{.Settings.Env}}' 2>/dev/null | grep -q "$(NETWORK_PLUGIN_MODES_ENV)="; }; \
	if [ -z "$(FORCE)" ] && has_modes; then \
		docker plugin enable "$$plugin" >/dev/null 2>&1 || true; \
		echo "Network plugin $$plugin already has the switch types"; exit 0; \
	fi; \
	networks=$$(docker network ls -q --filter "driver=$$plugin" | wc -l); \
	if [ "$$networks" -ne 0 ]; then \
		echo "ERROR: $$networks network(s) use $$plugin: stop the running projects first (sre wipe)"; exit 1; \
	fi; \
	docker plugin rm -f "$$plugin" >/dev/null 2>&1 || true; \
	if [ -z "$(BUILD)" ]; then \
		image="$(NETWORK_PLUGIN_IMAGE):$$arch"; \
		if docker plugin install --grant-all-permissions --alias "$$plugin" "$$image" && has_modes; then \
			echo "Network plugin $$plugin installed from $$image: hub, switch and managed switch"; exit 0; \
		fi; \
		echo "No usable plugin published as $$image: building it from the sources"; \
		docker plugin rm -f "$$plugin" >/dev/null 2>&1 || true; \
	fi; \
	rm -rf "$(NETWORK_PLUGIN_DIR)"; mkdir -p "$$(dirname "$(NETWORK_PLUGIN_DIR)")"; \
	git clone --depth 1 --branch "$(NETWORK_PLUGIN_BRANCH)" "$(NETWORK_PLUGIN_REPO)" "$(NETWORK_PLUGIN_DIR)"; \
	build="make -C $(NETWORK_PLUGIN_DIR)/vde all_$$arch PLUGIN_NAME=$(NETWORK_PLUGIN_NAME)"; \
	echo "Building $$plugin (a few minutes)"; \
	if [ -t 0 ]; then $$build; else script -qefc "$$build" /dev/null; fi; \
	docker plugin enable "$$plugin"; \
	rm -rf "$(NETWORK_PLUGIN_DIR)"; \
	has_modes || { echo "ERROR: $$plugin does not advertise $(NETWORK_PLUGIN_MODES_ENV)"; exit 1; }; \
	echo "Network plugin $$plugin built and installed: hub, switch and managed switch"

venv: fonts
	# Always start from a clean slate. `python3 -m venv` over an existing
	# directory only partially refreshes it and won't rewrite shebangs whose
	# absolute paths point outside the tree (e.g. when the project was moved
	# or rsynced from a prior install root).
	rm -rf ${ROOT_DIR}/venv
	python3.13 -m venv ${ROOT_DIR}/venv
	${ROOT_DIR}/venv/bin/pip install setuptools
	${ROOT_DIR}/venv/bin/pip install "kathara @ git+https://github.com/emotchane/Kathara.git@main"
	${ROOT_DIR}/venv/bin/python3 -c 'import os, pathlib, site; sp = pathlib.Path(site.getsitepackages()[0]); pkg = sp / "pkg_resources"; pkg.mkdir(exist_ok=True); (pkg / "__init__.py").write_text(os.environ["PKG_RESOURCES_STUB"])'
	${ROOT_DIR}/venv/bin/pip install graphviz
	${ROOT_DIR}/venv/bin/pip install pyside6
	${ROOT_DIR}/venv/bin/pip install msgpack
	${ROOT_DIR}/venv/bin/pip install zstandard
	${ROOT_DIR}/venv/bin/pip install markdown
	${ROOT_DIR}/venv/bin/pip install fpdf2
	${ROOT_DIR}/venv/bin/pip install odfpy
	${ROOT_DIR}/venv/bin/pip install pytest
	${ROOT_DIR}/venv/bin/pip install netaddr
	${ROOT_DIR}/venv/bin/pip install cryptography

#	python3 -m pip install pyuv; \
#   python3 -m pip install graphviz;
translations:
	${ROOT_DIR}/venv/bin/pyside6-lupdate \
		src/sysreseval.py \
		src/sysreseval/main_window.py \
		src/sysreseval/open_project_dialog.py \
		src/sysreseval/project_widget.py \
		src/sysreseval/start_progress_dialog.py \
		src/sysreseval/wrapper_progress_dialog.py \
		src/sysreseval/flavor_form_dialog.py \
		src/sysreseval/settings_dialog.py \
		src/sysreseval/view/machines_view.py \
		src/sysreseval/view/switches_view.py \
		src/sysreseval/view/questions_view.py \
		src/sysreseval/view/evaluations_view.py \
		src/sysreseval/view/apply_config_view.py \
		src/sysreseval/view/schema_view.py \
		src/sysreseval/view/log_view.py \
		-ts translations/sysreseval_fr.ts
	${ROOT_DIR}/venv/bin/pyside6-lrelease \
		translations/sysreseval_fr.ts \
		-qm translations/sysreseval_fr.qm
	xgettext --language=Python --keyword=_ --join-existing --no-location \
		-o locale/fr/LC_MESSAGES/sre.po \
		src/sre.py
	msgfmt locale/fr/LC_MESSAGES/sre.po -o locale/fr/LC_MESSAGES/sre.mo

wrappers:
	@grep -qP '^debug_mode\s*=\s*True' ${ROOT_DIR}/src/SRE/params.py \
		&& { echo "ERROR: debug_mode is True in params.py — refusing to build"; exit 1; } || true
	chmod 755 ${ROOT_DIR}/sbin/sre ${ROOT_DIR}/bin/sysreseval

sre-wrapper:
	gcc -O2 -Wall -o ${ROOT_DIR}/bin/sre-wrapper ${ROOT_DIR}/src/sre-wrapper/sre-wrapper.c
	strip ${ROOT_DIR}/bin/sre-wrapper
	chmod 711 ${ROOT_DIR}/bin/sre-wrapper


install: check-debug-mode fonts sre-wrapper wrappers

check-debug-mode:
	@grep -qP '^debug_mode\s*=\s*True' ${ROOT_DIR}/src/SRE/params.py \
		&& { echo "ERROR: debug_mode is True in params.py — refusing to install"; exit 1; } || true

set-debug-mode:
	@sed -i 's/^debug_mode\s*=\s*False/debug_mode = True/' ${ROOT_DIR}/src/SRE/params.py
	@grep -qP '^debug_mode\s*=\s*True' ${ROOT_DIR}/src/SRE/params.py \
		&& echo "debug_mode = True" || { echo "ERROR: failed to set debug_mode"; exit 1; }

remove-debug-mode:
	@sed -i 's/^debug_mode\s*=\s*True/debug_mode = False/' ${ROOT_DIR}/src/SRE/params.py
	@grep -qP '^debug_mode\s*=\s*False' ${ROOT_DIR}/src/SRE/params.py \
		&& echo "debug_mode = False" || { echo "ERROR: failed to unset debug_mode"; exit 1; }



tests:
	${ROOT_DIR}/venv/bin/python -m pytest ${ROOT_DIR}/tests/ -v -p no:cacheprovider --ignore=${ROOT_DIR}/tests/test_exam_mode.py --ignore=${ROOT_DIR}/tests/test_docker_lifecycle.py

# Run a single test file: make test FILE=test_net_config.py
FILE ?=
test:
	${ROOT_DIR}/venv/bin/python -m pytest ${ROOT_DIR}/tests/$(FILE) -v -p no:cacheprovider --ignore=${ROOT_DIR}/tests/test_exam_mode.py --ignore=${ROOT_DIR}/tests/test_docker_lifecycle.py

functional-tests:
	rm -rf /tmp/pytest-sre-functional
	${ROOT_DIR}/venv/bin/python -m pytest ${ROOT_DIR}/tests/test_functional.py -v -p no:cacheprovider --basetemp=/tmp/pytest-sre-functional

# Exam-mode integration tests (run as root/sre user).
# Usage: make exam-tests [EXAM_USER=etudiant] [EXAM_LAB=...] [EXAM_LAB2=...] [SCENARIOS="1 4 8"]
#        make exam-tests SCENARIO=1   # single scenario shorthand
EXAM_USER ?= etudiant
EXAM_LAB  ?= _TESTS_/exam_test1.py
EXAM_LAB2 ?= _TESTS_/exam_test2.py
EXAM_ARGS  = --user $(EXAM_USER) --lab $(EXAM_LAB) --lab2 $(EXAM_LAB2) \
             --sre $(ROOT_DIR)/sbin/sre --sysreseval $(ROOT_DIR)/bin/sysreseval
ifdef SCENARIO
EXAM_ARGS += $(SCENARIO)
else ifneq ($(SCENARIOS),)
EXAM_ARGS += $(SCENARIOS)
endif

exam-tests:
	@grep -qP '^debug_mode\s*=\s*True' ${ROOT_DIR}/src/SRE/params.py \
		|| { echo "ERROR: debug_mode is False in params.py — set debug_mode = True before running exam-tests"; exit 1; }
	PYTHONPATH=${ROOT_DIR}/src ${ROOT_DIR}/venv/bin/python ${ROOT_DIR}/tests/test_exam_mode.py $(EXAM_ARGS)

# Docker integration tests with real containers (run as root on a host with Docker and the SRE images):
# sre start/stop for a non-privileged and a privileged lab, sre save/restore, checked on the Docker API.
docker-tests:
	${ROOT_DIR}/venv/bin/python -m pytest ${ROOT_DIR}/tests/test_docker_lifecycle.py -v -p no:cacheprovider

all-tests: tests functional-tests exam-tests docker-tests

images:
	$(MAKE) -C ${ROOT_DIR}/images all
	@sed -i 's|^default_docker_image_version[[:space:]]*=.*|default_docker_image_version = "$(IMAGES_VERSION)"|' ${ROOT_DIR}/src/SRE/params.py
	@grep '^default_docker_image_version' ${ROOT_DIR}/src/SRE/params.py

