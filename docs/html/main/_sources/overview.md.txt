# Overview

**SysResEval** (or **SRE**, for *Système Réseaux Évaluation*) is a software suite for managing exercise sessions and evaluations in network and system administration courses. It is built on top of the [Kathara framework](https://github.com/KatharaFramework/Kathara), using Docker containers and VDE networking.[^1]

It was developed at **IUT d'Orsay, Université Paris-Saclay** (France).

[^1]: A first version was made with [Marionnet](https://www.marionnet.org/) and then rebuilt from scratch on Kathara / Docker.

SysResEval can be used by students autonomously, in supervised exercise sessions, or in time-limited evaluations.

Students interact only with a GUI, `sysreseval`, which calls the `sre` CLI
on their behalf through the small `sre-wrapper` setuid helper
The instructor can also use the CLI to set up an exam, start a project for a student, connect to a machine, 
launch an eval, etc...

## Student Workflow

The student starts the **sysreseval** GUI, then chooses and opens a *lab*.[^2] Each lab presents several tabs:

- **Schema** — the network topology. By default, machines that disallow connection are drawn in red, but every lab can override colors and shapes for machines and networks. Some machines may be hidden from the diagram entirely.
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

The **Questions**, **Evaluations**, and **Apply Configuration** tabs are optional 
and are shown only when the lab defines them.

**Multiple labs can be open at once**, letting a course be
structured by topic instead of by session.

## Monitoring of a session

During an exercices session, an instructor with the `sre watch` tool can monitor a whole class:
- consult the last evaluation result of any student (evaluations run periodically — the interval is a per-project parameter, 
typically one minute — even when the student does not trigger a self-evaluation).
- be alerted about any error during evaluations or by the lack of a recent evaluation
- display a list of all "grade elements" and the max, min and average grade of the students

The grade elements shown to the instructor can differ from those the student sees during a self-evaluation. For example, 
on a static routing exercise, the instructor may see detailed items (IPv4 address, default route,
indirect route toward network A, etc.) while the student only sees a single "Configuration of machine m1".

## Running exams

sysreseval manages time-limited exams. The instructor configures
the exam and sysreseval starts each student's project — either
immediately or at a scheduled time — displays a countdown,
runs periodic evaluations (by default every 60 seconds), and shows
a banner when the allotted time is up.


The instructor can change the duration during the exam, or even
after it ends — the virtual machines are not stopped at the end
(in practice, it is often easier to set a single duration
for the whole class with a `dsh` call, then adjust it
individually for students with special accommodations)

The student's final mark is the best overall grade across their
evaluations.


## Post-exam workflow

Each evaluation produces an archive file containing all of its data,
readable via `sre cat`. If a student questions their score, the
instructor can give a full explanation — for example, for a question about routing,  by showing
the output of `ip route` on m1 to reveal which routes were in place
at the time. During exams, all terminal sessions are also recorded
as asciinema files.

After the exam, the instructor can re-run the evaluation script —
for instance to adjust the relative weight of items, or to fix a
bug in the script — and then generate a per-student PDF with a
detailed item-by-item breakdown, plus a recap ODS spreadsheet.


[^2]: The word *lab* comes from Kathara (and Netkit). We use *lab* and *project* interchangeably in this documentation.

