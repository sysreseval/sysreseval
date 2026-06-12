<p align="right">
  <strong>English</strong> · <a href="README.fr.md">Français</a>
</p>

<p align="center">
  <img src="graphics/sysreseval.svg" alt="SysResEval logo" width="140">
</p>

<h1 align="center">SysResEval (SRE)</h1>

<p align="center">
  <a href="https://sysreseval.github.io/sysreseval/html/main/index.html">Main docs (HTML)</a> ·
  <a href="https://sysreseval.github.io/sysreseval/html/api/index.html">API reference</a> ·
  <a href="docs/documentation.pdf">PDF manual</a>
</p>

---

**SysResEval** (*Système Réseaux Évaluation*, shortened to **SRE**) is an open-source software suite for teaching and managing exercise sessions and evaluations in network and system administration courses.
Each "lab" or project is a small virtual network of Linux machines, orchestrated through the [Kathara framework](https://github.com/KatharaFramework/Kathara) on top of Docker and VDE. 
Students work through guided exercises in a GUI; 
instructors monitor sessions and run time-limited exams with automatic, reproducible grading.

It is developed at the **IUT d'Orsay, Université Paris-Saclay**.

## Highlights

- **Two-tier interface.** A desktop GUI (`sysreseval`) for students, plus a full-featured CLI (`sre`) for instructors and authors. The GUI shells out to the CLI through a small setuid `sre-wrapper` helper, so privilege boundaries stay clean.
- **Rich lab structure.** Every lab present several tabs:
  - **Schema** — the network topology (some machines may disallow connection (in red) or be hidden)
  - **Informations** — general background and instructions, written in Markdown.
  - **Questions** — a list of items the student must complete. Each question is one of:
    - a Markdown text describing a task to perform on the machines (e.g. *configure the network on m1*),
    - a form whose fields capture specific facts (e.g. *what is the MTU of `eth0` on m1?*); fields may be free-text validated by a regexp (e.g. an IPv4 address), a dropdown, or a checkbox,
    - a free-form multi-line text answer.
  - **Terminals** — an embedded shell for each machine the student is allowed to connect to. A lab may expose these as plain root shells or, for example, as a `login` prompt that restricts students to a particular user account.
  - **Machines** — a status table for each machine: state, NAT network, exposed ports. The students can use it to launch separate terminals sessions to
  a machine (useful when several terminal sessions are needed on one machine)
  - **Evaluations** — lets the student trigger an automated evaluation of their work and view the resulting grade table.
  - **Apply Configuration** — lets the student put the project into a predefined state, for example a partial correction.
- **Multiple labs open at once.** Course content can be organised by topic rather than by session — students can keep several projects running and switch between them.
- **Live classroom monitoring.** Instructors can watch the whole class in real time, inspect each student's latest evaluation and grading errors, and see per-item min/max/average statistics across the class.
- **Time-limited exams.** `sysreseval` starts each student's project (immediately or at a scheduled time), shows a countdown, runs periodic evaluations, and posts an end-of-exam banner. Duration can be adjusted on the fly — useful for accommodations.
- **Reproducible grading and post-exam tooling.** Each evaluation is archived as a compressed msgpack file capturing the project data, raw command outputs, student answers, and per-item grades — inspect any archive with `sre cat`.
If a grading bug surfaces after the fact, `sre re-eval` re-runs the scoring against an updated script; `sre outline` then produces per-student PDF reports and a recap ODS spreadsheet. During exams, every terminal session is also saved as an asciinema cast for later review.
- **Internationalisable.** Lab strings and GUI translations ship in French and English; tools (`prepare-sre-translations`, `add-sre-translations`) make multilingual authoring straightforward.


## Example

<p align="center">
  <img src="docs/demo1.gif" alt="SysResEval demo" width="800">
</p>
<p align="center">
  <a href="https://github.com/sysreseval/sysreseval/raw/main/docs/demo1.mp4">Download the full-quality video (MP4)</a>
</p>


## Installation

SRE is a Linux server-side install (Debian/Ubuntu, any other distros with manual dependency installation). 
Production deployments live under `/opt/sre` and are typically shared across a classroom via NFS.

```bash
git clone https://github.com/sysreseval/sysreseval /opt/sre
cd /opt/sre
sudo ./scripts/install.sh        # interactive — ~10 questions
```

The installer creates the `sre` system user, drops a sudoers rule, builds the C wrapper and Python venv, and (optionally) installs a `.desktop` entry, bash completion, and a `sre-preload-images.service` systemd unit. 

See **[docs/sphinx/installation.md](docs/sphinx/installation.md)** for the post-install set-up:
- raising inotify limits,
- configure X to listen to TCP port 6000,
- restricting student access to Docker during exams,
- sharing archive directories for live monitoring,
- pre-loading Docker images to avoid a network meltdown when an exam starts.

Full step-by-step setup, manual install, and post-install steps are documented in **[docs/sphinx/installation.md](docs/sphinx/installation.md)**.


## Documentation

- [Overview](https://sysreseval.github.io/sysreseval/html/main/overview.html)
- [Installation & deployment](https://sysreseval.github.io/sysreseval/html/main/installation.html)
- [Running exams](https://sysreseval.github.io/sysreseval/html/main/exam.html) · [exam reference](https://sysreseval.github.io/sysreseval/html/main/exam-reference.html)
- [Authoring labs](https://sysreseval.github.io/sysreseval/html/main/lab-authoring.html) · [translations](https://sysreseval.github.io/sysreseval/html/main/translations.html)
- [CLI reference](https://sysreseval.github.io/sysreseval/html/main/cli.html) · [GUI reference](https://sysreseval.github.io/sysreseval/html/main/gui.html)
- [Runtime & internals](https://sysreseval.github.io/sysreseval/html/main/internals.html)

