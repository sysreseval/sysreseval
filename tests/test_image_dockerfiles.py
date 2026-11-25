"""The child images of images/: the apt lists and caches leave the image in the step that made them.

A RUN that installs packages and a later RUN that runs `apt-get clean && rm -rf /var/lib/apt/lists/*`
leave the lists and `/var/cache/apt/*.bin` in the layer of the first one: about 15 MB compressed per
image (the former ntp13 image was 18 MB above base13 for a 0.7 MB package).  These tests read the
Dockerfiles only (no Docker).  base12 / base13 build the system in many steps from one `apt-get
update` and clean once at the end: left out.  Only the stages the image is built from count (the
final stage and the stages it names in FROM), not the build stages it copies files from.
"""
import re
from pathlib import Path

import pytest

IMAGES_DIR = Path(__file__).parent.parent / 'images'
LEFT_OUT = ('base12', 'base13')
INSTALL = re.compile(r'\bapt(-get)?\s+(-\S+\s+)*install\b')
CLEAN = re.compile(r'\bapt(-get)?\s+clean\b')
LISTS = re.compile(r'\brm\s+-rf\s+[^&;|]*/var/lib/apt/lists/\*')


def instructions(text: str) -> list[tuple[str, str]]:
    """``(KEYWORD, arguments)`` of every instruction of a Dockerfile, continuation lines joined
    and comment lines dropped (a here-document is not used by these images)."""
    result, current = [], ''
    for line in text.splitlines():
        stripped = line.strip()
        if not current and (not stripped or stripped.startswith('#')):
            continue
        if current and stripped.startswith('#'):
            continue
        if stripped.endswith('\\'):
            current += stripped[:-1].rstrip() + ' '
            continue
        current += stripped
        keyword, _, args = current.partition(' ')
        result.append((keyword.upper(), args.strip()))
        current = ''
    return result


def image_stages(text: str) -> list[list[tuple[str, str]]]:
    """The instructions of the stages the image is built from: the last stage, then the stage it
    names in FROM, and so on (a FROM naming an image outside the file ends the chain)."""
    stages, names = [], {}
    for keyword, args in instructions(text):
        if keyword == 'FROM':
            words = args.split()
            if len(words) == 3 and words[1].upper() == 'AS':
                names[words[2]] = len(stages)
            stages.append([(keyword, args)])
        elif stages:
            stages[-1].append((keyword, args))
    chain, index = [], len(stages) - 1
    while index is not None:
        chain.append(stages[index])
        index = names.get(stages[index][0][1].split()[0])
    return chain


def child_images() -> list[str]:
    if not IMAGES_DIR.is_dir():
        return []
    return sorted(d.name for d in IMAGES_DIR.iterdir()
                  if (d / 'Dockerfile').is_file() and d.name not in LEFT_OUT)


@pytest.mark.skipif(not IMAGES_DIR.is_dir(), reason=f"no {IMAGES_DIR} in this tree")
@pytest.mark.parametrize('image', child_images())
def test_every_install_cleans_in_the_same_step(image):
    text = (IMAGES_DIR / image / 'Dockerfile').read_text()
    runs = [args for stage in image_stages(text) for keyword, args in stage if keyword == 'RUN']
    installs = [run for run in runs if INSTALL.search(run)]
    for run in installs:
        assert CLEAN.search(run) and LISTS.search(run), f"{image}: {run[:120]}"


class TestParsing:
    DOCKERFILE = """ARG X=1
# a comment
FROM debian:13 AS build
RUN apt-get update && apt-get install -y gcc
FROM ns/init13:1 AS tools
RUN apt-get update \\
    # a comment line inside the instruction
    && apt-get install -y --no-install-recommends vim \\
    && apt-get clean && rm -rf /tmp/* /var/lib/apt/lists/*
FROM debian:13-slim AS box
RUN apt-get install -y sshd
FROM tools
COPY --from=build /out /
"""

    def test_instructions_join_the_continuation_lines(self):
        runs = [args for keyword, args in instructions(self.DOCKERFILE) if keyword == 'RUN']
        assert runs[1] == ("apt-get update && apt-get install -y --no-install-recommends vim "
                           "&& apt-get clean && rm -rf /tmp/* /var/lib/apt/lists/*")

    def test_the_stages_of_the_image(self):
        chain = image_stages(self.DOCKERFILE)
        assert [stage[0][1] for stage in chain] == ['tools', 'ns/init13:1 AS tools']

    def test_a_separate_clean_is_refused(self):
        run = "apt update && apt install -y chrony"
        assert INSTALL.search(run) and not CLEAN.search(run)

    def test_the_images_of_the_tree(self):
        if not IMAGES_DIR.is_dir():
            pytest.skip(f"no {IMAGES_DIR} in this tree")
        assert {'netdev13', 'identity13', 'devops13'} <= set(child_images())
