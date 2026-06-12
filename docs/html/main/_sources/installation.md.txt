# Installation and Setup

## Prerequisites

- A Linux host. `scripts/install.sh` knows how to `apt-get install` missing packages on Debian and Ubuntu; 
on anything else you must install the prerequisites yourself.
- **Root** access. The installer refuses to start unless `EUID == 0` (run with `sudo`).
- The **Docker daemon running**, with `/var/run/docker.sock` present. The installer reads the socket's GID and grants the `sre` user access to it; if the socket is missing it aborts with a hint to start the daemon.
- **Python 3.13**. On Ubuntu < 24.04 you may need the `deadsnakes` PPA; on Debian < 13 you need to upgrade or build it from source. The installer will offer to `apt-get install python3.13` on Debian-likes.

These tools must already be on `PATH` (always present on a POSIX system): `sed grep stat getent useradd groupadd usermod install`.

These tools are auto-installed via `apt-get` on Debian-likes if missing: 
- `docker` (any variety)
`asciinema`
`make gcc`
`graphviz`
`python3.13`

On other distributions install them with your package manager before running the installer.

## Deployment layout

SRE's runtime root defaults to `/opt/sre`, but the installer makes it configurable. Clone the repo (`git clone https://github.com/sysreseval/sysreseval /opt/sre`) or untar the release into `/opt/sre` — or into any other location you prefer.

`scripts/install.sh` detects where it is being run from and offers that path as the default — `/opt/sre` when run from `/opt/sre/scripts/`, 
otherwise the parent of the script directory. The chosen value is patched into `src/SRE/params.py` (`main_sre_dir`) and substituted for `/opt/sre` in the sudoers rule, 
the `.desktop` file, and the `sre-preload-images.service` unit at install time. 

The installer is **interactive** — it asks roughly ten configuration questions, then creates the `sre` user, installs a sudoers file, and runs the build — and is meant to be run **once per build**, not once per student workstation. The trick to scaling from a single interactive run to a classroom of student machines is to share the resulting runtime tree (and replay a small per-host setup on each workstation). The rest of this document uses `/opt/sre` as the canonical example path; substitute your `main_sre_dir` wherever it appears if you chose something else.

Two common topologies:

**Single read-only NFS export (recommended for classrooms).** Clone the repo on a build server inside the directory you intend to export, run `sudo ./scripts/install.sh` 
there once, then export the directory read-only and mount it as `/opt/sre` on every student workstation. Updates take effect everywhere as soon as the export is refreshed, 
and students cannot tamper with the binaries or with the project files. The shell wrappers in `sbin/` and `bin/` don't write to their own tree,
and all runtime state lives elsewhere — `/var/lib/sre` (`sre_pub_dir`) and `/home/sre` (`sre_user_public_dir`) stay on the local workstation — so a read-only mount works.

**Build once, replicate per workstation.** Run the installer once on a reference machine cloned at `/opt/sre`, then `rsync` (or image-clone) the resulting `/opt/sre` tree to every workstation. Running `install.sh` interactively on each machine is impractical for more than a handful of hosts.

**Either way, each student workstation still needs a few per-host bits that aren't part of the `/opt/sre` tree**:

- the `sre` system user/group, with the UID/GID baked into `params.py` at build time
- `/etc/sudoers.d/sre`
- membership of `sre` in the local `docker` group
- a copy of `scripts/etc/sre_bash_completion` into `/etc/bash_completion.d/sre`
- a copy of `scripts/etc/sysreseval.desktop` into `/usr/share/applications/`
- raised inotify limits and other post-install steps (see [Post-install steps](#post-install-steps))
- for the NFS topology, the mount itself

Script these from the relevant sections of `scripts/install.sh` if you have many machines.

The `/opt/sre` tree must contain `lab/`, `lib/`, `graphics/`, `translations/`, `locale/`, `bin/`, `sbin/`, `src/`, `venv/`. Lab authors also browse `src/` while writing `srelab.py` files. See [Runtime & Internals](internals.md) for the expected layout.

If you'd rather build in a separate working checkout (CI runner, personal dev tree) and move the result over afterwards, `rsync` or bind-mount the built tree into `/opt/sre` once `make install` has finished, then continue with the [Post-install steps](#post-install-steps).

## Running the installer

```bash
sudo ./scripts/install.sh
```

The script is interactive. It asks, in order:

| Prompt | Default | Purpose |
|--------|---------|---------|
| `main_sre_dir` | `/opt/sre` if the script is at `/opt/sre/scripts/`, otherwise the script's parent directory | Runtime root for SRE binaries, libs, labs, graphics, translations, locale. Substituted for `/opt/sre` in the sudoers rule, `.desktop` file, and systemd unit at install time. |
| `sre` UID | `1100` | UID of the system user that owns running labs. |
| `sre` GID | `1100` | GID of the matching group. |
| `sre_pub_dir` | `/var/lib/sre` | Public state: running projects, archives, `exam.json`. |
| `sre_user_public_dir` | `/home/sre` | Per-lab shared `/home/sre/{running_lab}` mounts. |
| `allow_privileged_machines` | `y` | Whether `srelab.py` files may declare privileged containers. |
| `execute_commands_on_host` | `shell` | `shell`, `split`, or `False` — controls how lab `host_cmd()` calls are executed. |
| extra authorized src dirs | `/home` | Extra directories (beyond `main_sre_dir + '/lab'`, which is always included) from which `srelab.py` files may be loaded. Type `-` for none to restrict loading to the lab directory only. |
| Admin UIDs / GIDs | _(none)_ | Extra UIDs/GIDs that SRE treats as administrators. |

The Docker socket GID is detected automatically (no prompt).

After you confirm the summary, the installer:

1. Saves a backup of `params.py` to `params.py.bak.<YYYYmmdd-HHMMSS>`.
2. Patches the answers into `src/SRE/params.py` (single-line `key = value` substitutions, each verified after the edit).
3. Runs `make remove-debug-mode` if `debug_mode = True` is currently set — `make install` refuses to build while debug mode is on.
4. Creates the `sre` system group and user (`nologin` shell, home `/home/sre`) if they don't already exist. If a user/group with the requested name exists with a different UID/GID, it is **kept as-is** rather than overwritten — the installer warns and continues.
5. Adds `sre` to the Docker group resolved from the socket GID.
6. Installs `/etc/sudoers.d/sre` (**required** — the `sysreseval` GUI shells out to `sudo /opt/sre/sbin/sre --user` via `sre-wrapper`, so labs cannot start without this rule), validated by `visudo -c` before being kept. The rule it installs is:
   ```
   Defaults!/opt/sre/sbin/sre env_keep += "USER_USERNAME SRE_XAUTH_COOKIE"
   ALL  ALL= NOPASSWD: /opt/sre/sbin/sre --user *
   ```
   The rule grants passwordless access to every user on the host, not a specific group — `sre-wrapper` is the only entry point and it always passes `--user` with the caller's real login, so widening the sudoers scope doesn't lower the security envelope. Restrict it to a specific group (e.g. `%etudiant`) if your site policy requires it.
7. Optionally installs `scripts/etc/sysreseval.desktop` to `/usr/share/applications/` so the GUI appears in the desktop application menu.
8. Optionally installs `scripts/etc/sre_bash_completion` to `/etc/bash_completion.d/sre` so the `sre` CLI gets bash completion system-wide.
9. Optionally installs the `sre-preload-images.service` systemd unit (oneshot, requires `opt-sre.mount`; not enabled by default — enable with `systemctl enable --now sre-preload-images.service` once `/opt/sre` is mounted).
10. Runs `make venv` then `make install` (which is `check-debug-mode` + `sre-wrapper` + `wrappers`).
11. Optionally creates symlinks in `/usr/local/bin/` and `/usr/local/sbin/` pointing to each executable under `main_sre_dir/bin/` and `main_sre_dir/sbin/`, so `sre`, `sysreseval`, and `sre-wrapper` can be launched without their full path. Existing non-symlink files at the same paths are left untouched (with a warning).

## Install manually

If you prefer to skip `scripts/install.sh` (e.g. on a non-Debian distribution, or to integrate with your own configuration management), perform the same steps by hand from a checkout of the repo:

1. **Create the `sre` system group and user.** Pick a UID/GID (the installer defaults to `1100`). The user needs a real home for shared `/home/sre/{running_lab}` mounts but no shell login:
   ```bash
   groupadd --system --gid 1100 sre
   useradd --system --uid 1100 --gid 1100 --home-dir /home/sre --shell /usr/sbin/nologin sre
   install -d -o sre -g sre -m 0755 /home/sre
   ```

2. **Add `sre` to the Docker group** so it can talk to `/var/run/docker.sock`:
   ```bash
   usermod -aG "$(stat -c %G /var/run/docker.sock)" sre
   ```

3. **Edit `src/SRE/params.py`** to match your site. At minimum review:
   - `main_sre_dir` — runtime root for SRE binaries, libs, labs, graphics, translations, locale (default `/opt/sre`). If you change this, also rewrite the literal `/opt/sre` in the sudoers rule, `.desktop` file, and `sre-preload-images.service` snippets below.
   - `sre_uid`, `sre_gid` — must match the user/group created above.
   - `docker_gid` — GID of the group owning `/var/run/docker.sock`.
   - `sre_pub_dir` — public state directory (default `/var/lib/sre`).
   - `sre_user_public_dir` — per-lab shared directory (default `/home/sre`).
   - `allow_privileged_machines` — whether `srelab.py` files may declare privileged containers.
   - `execute_commands_on_host` — `'shell'`, `'split'`, or `False`.
   - `authorized_src_dir` — list of directories from which `srelab.py` files may be loaded. Must include `main_sre_dir + '/lab'`; defaults to also including `/home`.
   - `admin_uids`, `admin_gids` — extra UIDs/GIDs treated as administrators.
   - `terminal_cmd_prefix`, `terminal_title_opt` — the external terminal emulator the GUI launches to open machine connections (default `mate-terminal`). Check which terminals are installed and uncomment the matching pair shown in `params.py`:
     ```bash
     command -v mate-terminal gnome-terminal xfce4-terminal xterm terminator
     ```
   - `debug_mode` — **must be `False`** before building (`make wrappers` refuses otherwise). Use `make remove-debug-mode` if needed.

4. **Install the sudoers rule** — required for `sysreseval` to start labs (the GUI invokes `sudo /opt/sre/sbin/sre --user` through `sre-wrapper`). The rule allows every user on the host to invoke the wrapper without a password; restrict the first column to a specific group (e.g. `%etudiant`) if your site policy requires it. Then validate before keeping the file:
   ```
   Defaults!/opt/sre/sbin/sre env_keep += "USER_USERNAME SRE_XAUTH_COOKIE"
   ALL  ALL= NOPASSWD: /opt/sre/sbin/sre --user *
   ```
   ```bash
   visudo -cf /etc/sudoers.d/sre && chmod 0440 /etc/sudoers.d/sre
   ```

5. **(Optional) Install the desktop entry** so the GUI appears in the desktop application menu:
   ```bash
   install -m 0644 -o root -g root scripts/etc/sysreseval.desktop /usr/share/applications/sysreseval.desktop
   ```

6. **(Optional) Install the image pre-pull systemd unit** from `scripts/etc/sre-preload-images.service` into `/etc/systemd/system/`. It requires `opt-sre.mount` and is not enabled by default — see [Pre-loading Docker images](#6-pre-loading-docker-images) below.

7. **(Optional) Install bash completion** for the `sre` CLI. The script under `scripts/etc/sre_bash_completion` completes subcommands, running lab names (read from `/var/lib/sre/projects/`), available labs (via `sre list`), and option arguments. 
Install it system-wide:
   ```bash
   cp scripts/etc/sre_bash_completion /etc/bash_completion.d/sre
   ```
   Or source it per-user from `~/.bashrc`:
   ```bash
   . /path/to/sre_bash_completion
   ```

8. **Build the venv and the binaries:**
   ```bash
   make venv      # creates venv/ with Python 3.13 deps — see Dependencies below
   make install   # check-debug-mode + sre-wrapper + wrappers
   ```

You can also run the CLI and GUI directly from source against the venv:

```bash
source venv/bin/activate
python3 -W ignore src/sre.py <command>     # CLI
python3 src/sysreseval.py                  # GUI
```

Most `sre` subcommands need root and a working Docker setup, but the pure-Python paths (e.g. `sre cat`, `sre sheet`, `sre outline`) work from a venv as a regular user against pre-existing archive files.

## Post-install steps

Once the installer has built the binaries, finish the deployment:

### 1. Deploy and verify

1. Make sure the built tree is reachable at `/opt/sre` on every workstation that will run labs. If you ran the installer from `/opt/sre` directly (per [Deployment layout](#deployment-layout)) this is already done; otherwise copy/bind-mount the built tree into place, or expose it via the read-only NFS export and mount it as `/opt/sre` on each workstation.
2. Verify Docker access for the `sre` user:
   ```bash
   sudo -u sre docker ps
   ```
   The Docker images SRE needs are pulled from Docker Hub on first lab start; no local image build is required.
3. Make sure `/opt/sre/bin` and `/opt/sre/sbin` are reachable on `PATH` so that `sysreseval`, `sre-wrapper`, and `sre` can be launched without their full path. The installer offers to create the symlinks under `/usr/local/bin` and `/usr/local/sbin` for you; if you skipped that prompt (or installed by hand), either add the two directories to the system-wide `PATH` (e.g. via `/etc/profile.d/sre.sh`), or create the symlinks manually:
   ```bash
   ln -s /opt/sre/bin/*  /usr/local/bin/
   ln -s /opt/sre/sbin/* /usr/local/sbin/
   ```

### 2. Raise inotify limits

Privileged labs run `/sbin/init` (systemd PID 1) inside each container, and systemd reserves inotify watches per cgroup. Debian defaults (`max_user_instances = 128`) are quickly exhausted once two privileged labs run side by side, after which systemd in any new container exits at startup with `Failed to create control group inotify object: Too many open files`. Drop in the file shipped under `scripts/etc/`:
```bash
cp scripts/etc/sre-inotify.conf /etc/sysctl.d/60-sre-inotify.conf
sysctl --system
```

(Optional) Tune `src/SRE/params.py` further — see [Runtime & Internals](internals.md).

### 3. Enable X11 access for lab virtual machines

Labs run graphical (X11) applications inside their containers and those apps display on the host's X server
(if the parameter `x11_host` is set to `True` in a virtual machine configuration).
For this to work the host's X server must accept TCP connections on **port 6000** (display `:0`). Modern X servers start with `-nolisten tcp`, so TCP is disabled by default and must be turned on explicitly. Access to individual labs is then authorized per project via an xauth cookie (`SRE_XAUTH_COOKIE` / `sre start --xauth-file`), so no `xhost` tweaks are needed — only the TCP listener.

How to enable TCP listening depends on your display manager. Two common cases:

- **GDM** — in `/etc/gdm3/custom.conf`:
  ```ini
  [security]
  DisallowTCP=false
  ```
- **LightDM** — in `/etc/lightdm/lightdm.conf` under `[Seat:*]`:
  ```ini
  xserver-allow-tcp=true
  ```

Restart the display manager (or log out and back in) for the change to take effect, then verify:
```bash
ss -ltn | grep 6000
```
You should see the X server listening on `0.0.0.0:6000` (and/or `[::]:6000`). `scripts/install.sh` runs this same check at the end and warns if no X server is listening on port 6000.

### 4. Restricting student access to Docker

For an exam to be meaningful, students must not be able to talk to Docker directly — otherwise a `docker exec -it ...` from a regular shell would let them connect to a forbidden container and bypass the lab's restrictions.

The recommended setup:

1. Remove students from the `docker` group entirely. Only `sre` (and any administrator account) should be a member.
2. Create a separate `docker-access` group and add the student accounts to it.
3. Toggle that group's access to `/var/run/docker.sock` with the two helpers shipped under `scripts/`:
   - `scripts/docker-allowed` grants `rw` on the socket to `docker-access` (run before non-exam sessions).
   - `scripts/docker-forbidden` revokes it (run before an exam).

Both helpers use `setfacl` on the Docker socket, so the change is immediate and survives until the next call.

### 5. Sharing evaluation archives for `sre watch`

`sre watch <directory>` runs an interactive terminal dashboard that monitors evaluation archives as they appear and alerts on student inactivity or errors.
To use it during an exercise session or an exam, every workstation must drop its archives into a directory the instructor can read from one place. 
Set the `archive_dirs` attribute in `params.py` (or on some lab's `srelab.py`) so evaluations are written into the shared location in addition to the local one.

There are several ways to set up the shared hierarchy:

**Single NFS share, server-side watch.** Export one NFS directory, restrict read-write access to the `sre` user (e.g. `rw,no_root_squash` for the workstations, mounted only as `sre`), and run `sre watch` directly on the NFS server. This is the simplest setup and works well when the instructor's session is on the server itself.

**Per-workstation NFS shares with nightly rotation.** Export one subdirectory per student workstation, each writable only by that workstation. The script `scripts/misc/rotate-nfs-dirs.py` is meant to be invoked from `cron` (typically once a night). On each run it:

1. Renames `/home/sre-archives/current` to `/home/sre-archives/YYYY-MM-DD` (the previous day), so past-day archives are no longer reachable from any student computer.
2. Re-creates `/home/sre-archives/current/<machine>` for every workstation listed in the `MACHINES` constant.
3. Rewrites `/etc/exports.d/sre-archives.exports` so each subdirectory is exported only to the matching workstation IP.
4. `systemctl reload nfs-kernel-server`.

Edit the `MACHINES`, `BASE_DIR`, and `EXPORTS_FILE` constants at the top of the script to match your site before installing the cron job. `sre watch /home/sre-archives/current` then sees every workstation's live archives.

**Read-only cross-mount for the instructor.** In addition to either of the above, you can re-export the shared directory read-only to the instructor's workstation. The instructor can then run `sre watch` from their own machine without logging into the server.

### 6. Pre-loading Docker images

When an exam starts, every workstation pulls the same images at the same time — without precaution this can saturate the network and cause a meltdown. The fix is to pre-pull the images on each host ahead of time.

The unit `scripts/etc/sre-preload-images.service` (offered for installation by `scripts/install.sh`) runs once at boot and shells out to:

```
/opt/sre/sbin/sre preload-images --random-delay 120 /opt/sre/lab/
```

The `--random-delay` spreads the pulls over a 120-second window so workstations don't hit Docker Hub simultaneously. The unit requires `opt-sre.mount` (i.e. `/opt/sre` mounted as a systemd mount unit) and is **not enabled by default**:

```bash
systemctl enable --now sre-preload-images.service
```

## Reference

### Build targets

| Target | Output |
|--------|--------|
| `make wrappers` | Marks `sbin/sre` and `bin/sysreseval` shell wrappers executable. Refuses to build while `params.debug_mode = True`. |
| `make sre-wrapper` | `bin/sre-wrapper` (small C helper that escalates via `sudo`). |
| `make install` | `check-debug-mode` + `sre-wrapper` + `wrappers`. |
| `make translations` | Compile Qt `.ts → .qm` and gettext `.po → .mo`. |
| `make docs` | API docs (pdoc) + main docs (Sphinx) → `docs/html/main/`, `docs/html/api/`, `docs/documentation.pdf`. |
| `make set-debug-mode` / `make remove-debug-mode` | Flip `debug_mode` in `src/SRE/params.py`. |

`debug_mode` must be `False` for `make wrappers` and `make install`, but **must be `True`** to run exam-mode integration tests — the GUI then emits the JSON event stream those tests assert on.

### Tests

```bash
make tests                          # unit tests (excludes test_exam_mode.py)
make test FILE=test_net_config.py   # single file
make functional-tests               # functional tests (test_functional.py)
make exam-tests                     # exam-mode integration tests (requires debug_mode=True)
make all-tests                      # tests + functional-tests + exam-tests
```

Unit tests don't need Docker or Kathara — they cover serialization, topology, grading logic, and pure-Python helpers. Functional and exam-mode tests stand up more of the system: see `tests/conftest.py` for the shared fixtures (`mock_sre_args`, `tmp_lab_dir`, `tmp_pub_dir`).

Pytest runs with `-p no:cacheprovider` so the production install (`/opt/sre/`, read-only) doesn't try to write a cache.

### Building the documentation

```bash
make docs            # api_doc + main_doc_pdf + main_doc_html
make main_doc_html   # Sphinx HTML only → docs/html/main/
make main_doc_pdf    # Sphinx LaTeX → docs/documentation.pdf
make api_doc         # pdoc API → docs/html/api/
```

The Sphinx targets pip-install `sphinx myst-parser furo` into the existing venv on demand; `api_doc` does the same for `pdoc`.

### Dependencies

Installed by `make venv`:

| Package | Purpose |
|---------|---------|
| `kathara` | Docker lab orchestration |
| `pyside6` | Qt6 GUI |
| `msgpack` | Efficient binary serialization |
| `zstandard` | Archive compression |
| `graphviz` | Network topology diagrams |
| `odfpy` | LibreOffice ODS spreadsheet export |
| `fpdf2` | PDF report generation |
| `markdown` | Lab description rendering |
| `netaddr` | MAC address handling |
| `pytest` | Test runner |

Documentation builds also fetch `sphinx`, `myst-parser`, `furo`, and `pdoc` on demand.
