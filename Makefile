
SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: venv translations wrappers sre-wrapper install check-debug-mode tests test functional-tests exam-tests all-tests set-debug-mode remove-debug-mode docs api_doc main_docs main_doc_pdf main_doc_html images

IMAGES_VERSION := $(shell awk '/^VERSION[[:space:]]*\??=/ {print $$NF; exit}' $(ROOT_DIR)/images/Makefile)

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
		lib.ips lib.net_config lib.dhcp lib.tls lib.grade_helpers lib.frr lib.state_helpers lib.utils
	@echo "Docs written to ${ROOT_DIR}/docs/html/api"

venv:
	# Always start from a clean slate. `python3 -m venv` over an existing
	# directory only partially refreshes it and won't rewrite shebangs whose
	# absolute paths point outside the tree (e.g. when the project was moved
	# or rsynced from a prior install root).
	rm -rf ${ROOT_DIR}/venv
	python3.13 -m venv ${ROOT_DIR}/venv
	${ROOT_DIR}/venv/bin/pip install setuptools
#	${ROOT_DIR}/venv/bin/pip install git+https://github.com/saghul/pyuv@master#egg=pyuv
	${ROOT_DIR}/venv/bin/pip install kathara
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

#	python3 -m pip install pyuv; \
#   python3 -m pip install graphviz;
translations:
	${ROOT_DIR}/venv/bin/pyside6-lupdate \
		src/sysreseval.py \
		src/sysreseval/main_window.py \
		src/sysreseval/open_project_dialog.py \
		src/sysreseval/project_widget.py \
		src/sysreseval/start_progress_dialog.py \
		src/sysreseval/settings_dialog.py \
		src/sysreseval/view/machines_view.py \
		src/sysreseval/view/questions_view.py \
		src/sysreseval/view/evaluations_view.py \
		src/sysreseval/view/apply_config_view.py \
		src/sysreseval/view/schema_view.py \
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


install: check-debug-mode sre-wrapper wrappers

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
	${ROOT_DIR}/venv/bin/python -m pytest ${ROOT_DIR}/tests/ -v -p no:cacheprovider --ignore=${ROOT_DIR}/tests/test_exam_mode.py

# Run a single test file: make test FILE=test_net_config.py
FILE ?=
test:
	${ROOT_DIR}/venv/bin/python -m pytest ${ROOT_DIR}/tests/$(FILE) -v -p no:cacheprovider --ignore=${ROOT_DIR}/tests/test_exam_mode.py

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

all-tests: tests functional-tests exam-tests

images:
	$(MAKE) -C ${ROOT_DIR}/images all
	@sed -i 's|^default_docker_image_version[[:space:]]*=.*|default_docker_image_version = "$(IMAGES_VERSION)"|' ${ROOT_DIR}/src/SRE/params.py
	@grep '^default_docker_image_version' ${ROOT_DIR}/src/SRE/params.py

