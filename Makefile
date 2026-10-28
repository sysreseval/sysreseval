
SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: venv fonts network-plugin deb release release-setup translations wrappers sre-wrapper install check-debug-mode tests test functional-tests exam-tests all-tests set-debug-mode remove-debug-mode docs api_doc main_docs main_doc_pdf main_doc_html images

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
		SRE.lib_sre SRE.common SRE.params SRE.informations \
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
# The recipe is scripts/network-plugin.sh (also /usr/sbin/sysreseval-network-plugin of the package).
network-plugin:
	@NETWORK_PLUGIN_REPO="$(NETWORK_PLUGIN_REPO)" NETWORK_PLUGIN_BRANCH="$(NETWORK_PLUGIN_BRANCH)" \
	NETWORK_PLUGIN_NAME="$(NETWORK_PLUGIN_NAME)" NETWORK_PLUGIN_IMAGE="$(NETWORK_PLUGIN_IMAGE)" \
	NETWORK_PLUGIN_MODES_ENV="$(NETWORK_PLUGIN_MODES_ENV)" NETWORK_PLUGIN_DIR="$(NETWORK_PLUGIN_DIR)" \
	FORCE="$(FORCE)" BUILD="$(BUILD)" $(ROOT_DIR)/scripts/network-plugin.sh

# Debian packages (python3-kathara, sysreseval, sysreseval-doc, and python3-fs on forky) built in
# a debian:$(DIST) container by scripts/build-deb.sh and checked by an installation in a second
# container: `make deb DIST=trixie` packages the working tree, `make deb DIST=forky REF=0.12.0`
# the release tagged 0.12.0 on GitHub.  Output in build/deb/$(DIST)/.
DIST ?= trixie
REF ?=
deb:
	$(ROOT_DIR)/scripts/build-deb.sh --dist $(DIST) $(if $(REF),--ref $(REF),--local) --test-install

# A release: `make release VERSION=0.13.2` bumps sre_version and debian/changelog, commits, tags,
# pushes, creates the GitHub release and waits for the release (packages) and pages (apt repository)
# workflows; `make release-setup` once for the signing key and GitHub Pages (scripts/release.sh).
VERSION ?=
release:
	@[ -n "$(VERSION)" ] || { echo "usage: make release VERSION=0.13.2"; exit 1; }
	$(ROOT_DIR)/scripts/release.sh $(VERSION)

release-setup:
	$(ROOT_DIR)/scripts/release.sh --setup

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
	# the web front-end (sre-web, sre-agent)
	${ROOT_DIR}/venv/bin/pip install aiohttp
	${ROOT_DIR}/venv/bin/pip install jinja2
	${ROOT_DIR}/venv/bin/pip install aiohttp-jinja2
	${ROOT_DIR}/venv/bin/pip install ldap3
	# the JavaScript syntax check of the web tests (pure Python; not in Debian trixie: the package build skips that test)
	${ROOT_DIR}/venv/bin/pip install esprima

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
	$(MAKE) -C ${ROOT_DIR} web-translations

wrappers:
	@grep -qP '^debug_mode\s*=\s*True' ${ROOT_DIR}/src/SRE/params.py \
		&& { echo "ERROR: debug_mode is True in params.py — refusing to build"; exit 1; } || true
	chmod 755 ${ROOT_DIR}/sbin/sre ${ROOT_DIR}/bin/sysreseval ${ROOT_DIR}/sbin/sre-agent ${ROOT_DIR}/sbin/sre-web ${ROOT_DIR}/sbin/sre-web-tool

sre-wrapper:
	gcc -O2 -Wall -o ${ROOT_DIR}/bin/sre-wrapper ${ROOT_DIR}/src/sre-wrapper/sre-wrapper.c
	strip ${ROOT_DIR}/bin/sre-wrapper
	chmod 711 ${ROOT_DIR}/bin/sre-wrapper


install: check-debug-mode fonts xterm novnc sre-wrapper wrappers

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

# The tests of the web front-end only (part of `make tests`): the agent on the fake sre of
# tests/mock_sre.py, the portal in front of it, the pty, the templates
web-tests:
	${ROOT_DIR}/venv/bin/python -m pytest ${ROOT_DIR}/tests/test_mock_sre.py ${ROOT_DIR}/tests/test_agent_runner.py ${ROOT_DIR}/tests/test_agent_main.py \
		${ROOT_DIR}/tests/test_agent_pty.py ${ROOT_DIR}/tests/test_agent_access.py ${ROOT_DIR}/tests/test_agent_registry.py \
		${ROOT_DIR}/tests/test_agent_api.py ${ROOT_DIR}/tests/test_agent_occupancy.py ${ROOT_DIR}/tests/test_web_config.py \
		${ROOT_DIR}/tests/test_web_identity.py ${ROOT_DIR}/tests/test_web_auth_proxy.py ${ROOT_DIR}/tests/test_web_portal.py \
		${ROOT_DIR}/tests/test_pool_manager.py ${ROOT_DIR}/tests/test_agent_terminals.py \
		${ROOT_DIR}/tests/test_archive_summary.py ${ROOT_DIR}/tests/test_web_auth_ldap.py \
		${ROOT_DIR}/tests/test_pool_admin.py ${ROOT_DIR}/tests/test_web_templates.py ${ROOT_DIR}/tests/test_web_tls.py \
		${ROOT_DIR}/tests/test_web_accesslog.py ${ROOT_DIR}/tests/test_web_presentation.py \
		${ROOT_DIR}/tests/test_agent_rfb_filter.py ${ROOT_DIR}/tests/test_web_stress.py \
		-v -p no:cacheprovider

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


# ---------------------------------------------------------------------------------------------
# Web front-end (src/sreweb, web/): translations and the vendored xterm.js
# ---------------------------------------------------------------------------------------------

.PHONY: web-translations xterm novnc

# The gettext catalog of the web front-end (domain "sreweb", src/sreweb/i18n.py): the strings
# of the Python sources and of the JavaScript modules are merged into the hand-maintained .po
# by xgettext.  xgettext cannot read the Jinja2 templates (web/templates/*.html): their
# _("...") strings are added to locale/fr/LC_MESSAGES/sreweb.po by hand (tests/test_web_templates.py
# checks that every string of the templates and of the JavaScript has a translation).
web-translations:
	xgettext --language=Python --keyword=_ --join-existing --no-location --from-code=UTF-8 \
		-o locale/fr/LC_MESSAGES/sreweb.po \
		src/sreweb/*.py src/sreweb/portal/*.py
	xgettext --language=JavaScript --keyword=_ --join-existing --no-location --from-code=UTF-8 \
		-o locale/fr/LC_MESSAGES/sreweb.po \
		web/static/js/*.js web/static/js/tabs/*.js
	msgfmt -o locale/fr/LC_MESSAGES/sreweb.mo locale/fr/LC_MESSAGES/sreweb.po

# xterm.js and its fit addon, vendored into web/static/vendor/xterm (the terminals of the web
# front-end; UMD builds loaded by web/templates/project.html).  Downloaded from unpkg at pinned
# versions and checked against their SHA-256, like the fonts; nothing to do when the files are
# already there.  Not committed: `make install` and the Debian build run this target.
XTERM_VERSION := 5.5.0
XTERM_FIT_VERSION := 0.10.0
XTERM_DIR := ${ROOT_DIR}/web/static/vendor/xterm
XTERM_BASE_URL := https://unpkg.com/@xterm/xterm@$(XTERM_VERSION)
XTERM_FIT_BASE_URL := https://unpkg.com/@xterm/addon-fit@$(XTERM_FIT_VERSION)
# file name, URL and SHA-256 of each vendored file (the LICENSE of the addon is the same MIT text
# with its own copyright line, kept as LICENSE-addon-fit)
XTERM_FILES := xterm.js xterm.css LICENSE addon-fit.js LICENSE-addon-fit
XTERM_URL_xterm.js := $(XTERM_BASE_URL)/lib/xterm.js
XTERM_URL_xterm.css := $(XTERM_BASE_URL)/css/xterm.css
XTERM_URL_LICENSE := $(XTERM_BASE_URL)/LICENSE
XTERM_URL_addon-fit.js := $(XTERM_FIT_BASE_URL)/lib/addon-fit.js
XTERM_URL_LICENSE-addon-fit := $(XTERM_FIT_BASE_URL)/LICENSE
XTERM_SHA256_xterm.js := 1f991ac3b4b283ebf96e60ae23a00a52765dd3a2e46fa6fdda9f1aab032f7495
XTERM_SHA256_xterm.css := ba8e6985669488981ccf40c0cefe3aba80722cb6c92de7ad628b0bd717faf2b6
XTERM_SHA256_LICENSE := b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd
XTERM_SHA256_addon-fit.js := bdaefa370b1bfc42ee88d46fe6072400902a4d4b2d45cd93438dda9b23c97089
XTERM_SHA256_LICENSE-addon-fit := e256f01188af527e4d06d21d06fbf785ae9c50d4b328bf03cbe0ba7f0aa4228f

xterm:
	@set -e; \
	missing=0; for f in $(XTERM_FILES); do [ -s "$(XTERM_DIR)/$$f" ] || missing=1; done; \
	if [ $$missing -eq 0 ]; then echo "xterm.js $(XTERM_VERSION) already in $(XTERM_DIR)"; exit 0; fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	echo "Downloading xterm.js $(XTERM_VERSION) and addon-fit $(XTERM_FIT_VERSION)"; \
	for f in $(XTERM_FILES); do \
		case $$f in \
			xterm.js) url="$(XTERM_URL_xterm.js)"; sha="$(XTERM_SHA256_xterm.js)";; \
			xterm.css) url="$(XTERM_URL_xterm.css)"; sha="$(XTERM_SHA256_xterm.css)";; \
			LICENSE) url="$(XTERM_URL_LICENSE)"; sha="$(XTERM_SHA256_LICENSE)";; \
			addon-fit.js) url="$(XTERM_URL_addon-fit.js)"; sha="$(XTERM_SHA256_addon-fit.js)";; \
			LICENSE-addon-fit) url="$(XTERM_URL_LICENSE-addon-fit)"; sha="$(XTERM_SHA256_LICENSE-addon-fit)";; \
		esac; \
		curl -fsSL -o "$$tmp/$$f" "$$url"; \
		if command -v sha256sum >/dev/null 2>&1; then sum=$$(sha256sum "$$tmp/$$f"); \
		else sum=$$(shasum -a 256 "$$tmp/$$f"); fi; \
		[ "$${sum%% *}" = "$$sha" ] \
			|| { echo "ERROR: unexpected SHA-256 for $$url: $${sum%% *}"; exit 1; }; \
	done; \
	mkdir -p "$(XTERM_DIR)"; \
	for f in $(XTERM_FILES); do install -m 644 "$$tmp/$$f" "$(XTERM_DIR)/$$f"; done; \
	echo "xterm.js installed in $(XTERM_DIR)"

# noVNC, vendored into web/static/vendor/novnc (the Display tab of the web front-end: the virtual
# X desktop of a project; web/static/js/tabs/display.js imports core/rfb.js as an ES module, which
# needs vendor/pako).  The release archive of GitHub at a pinned tag, checked against its SHA-256;
# nothing to do when core/rfb.js is already there.  Not committed: `make install` and the Debian
# build run this target.
NOVNC_VERSION := 1.6.0
NOVNC_DIR := ${ROOT_DIR}/web/static/vendor/novnc
NOVNC_URL := https://github.com/novnc/noVNC/archive/refs/tags/v$(NOVNC_VERSION).tar.gz
NOVNC_SHA256 := 5066103959ef4e9b10f37e5a148627360dd8414e4cf8a7db92bdbd022e728aaa

novnc:
	@set -e; \
	if [ -s "$(NOVNC_DIR)/core/rfb.js" ]; then echo "noVNC $(NOVNC_VERSION) already in $(NOVNC_DIR)"; exit 0; fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	echo "Downloading noVNC $(NOVNC_VERSION)"; \
	curl -fsSL -o "$$tmp/novnc.tar.gz" "$(NOVNC_URL)"; \
	if command -v sha256sum >/dev/null 2>&1; then sum=$$(sha256sum "$$tmp/novnc.tar.gz"); \
	else sum=$$(shasum -a 256 "$$tmp/novnc.tar.gz"); fi; \
	[ "$${sum%% *}" = "$(NOVNC_SHA256)" ] \
		|| { echo "ERROR: unexpected SHA-256 for $(NOVNC_URL): $${sum%% *}"; exit 1; }; \
	tar -xzf "$$tmp/novnc.tar.gz" -C "$$tmp" "noVNC-$(NOVNC_VERSION)/core" "noVNC-$(NOVNC_VERSION)/vendor/pako" \
		"noVNC-$(NOVNC_VERSION)/LICENSE.txt"; \
	rm -rf "$(NOVNC_DIR)"; mkdir -p "$(NOVNC_DIR)"; \
	cp -R "$$tmp/noVNC-$(NOVNC_VERSION)/core" "$$tmp/noVNC-$(NOVNC_VERSION)/vendor" "$(NOVNC_DIR)/"; \
	install -m 644 "$$tmp/noVNC-$(NOVNC_VERSION)/LICENSE.txt" "$(NOVNC_DIR)/LICENSE.txt"; \
	find "$(NOVNC_DIR)" -type d -exec chmod 755 {} +; find "$(NOVNC_DIR)" -type f -exec chmod 644 {} +; \
	echo "noVNC installed in $(NOVNC_DIR)"
