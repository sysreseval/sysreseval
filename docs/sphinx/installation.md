# Installation and Setup

## Prerequisites

- A Linux host. `scripts/install.sh` knows how to `apt-get install` missing packages on Debian and Ubuntu; 
on anything else you must install the prerequisites yourself.
- **Root** access. The installer refuses to start unless `EUID == 0` (run with `sudo`).
- A **container engine**, asked first by the installer:
  - *Kathara* (the default): the **Docker daemon running**, with `/var/run/docker.sock` present. The installer reads the socket's GID and grants the `sre` user access to it; if the socket is missing it aborts with a hint to start the daemon.
  - *Podman*: no Docker at all. The machines are rootless containers of the `sre` user; the host needs systemd (see [Podman engine](#podman-engine-rootless-containers)).
- **Python 3.13**. On Ubuntu < 24.04 you may need the `deadsnakes` PPA; on Debian < 13 you need to upgrade or build it from source. The installer will offer to `apt-get install python3.13` on Debian-likes.
- **AppArmor** (on by default on Debian and Ubuntu) needs no action: the Kathara fork runs the non-privileged machines with the Docker option `apparmor=unconfined`, because Docker's `docker-default` profile denies the remount of `/proc/sys` and every write under `/proc/sys/net/` (the `initial` state of a lab could not reset `ip_forward`, and the students could not set it either; Docker runs the privileged machines unconfined by itself). With a stock Kathara, boot the host with `apparmor=0` on the kernel command line instead.

These tools must already be on `PATH` (always present on a POSIX system): `sed grep stat getent useradd groupadd usermod install`.

These tools are auto-installed via `apt-get` on Debian-likes if missing: 
- `docker` (any variety), for the Kathara engine only
- for the Podman engine: `podman`, `uidmap`, `vdeplug`, `passt`, `catatonit`, `dbus-user-session`, and `cmake` and `curl` to build its switch
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
- raised inotify limits (`scripts/etc/sre-inotify.conf` into `/etc/sysctl.d/`, then `sysctl --system`)
- the other post-install steps (see [Post-install steps](#post-install-steps))
- for the NFS topology, the mount itself

Script these from the relevant sections of `scripts/install.sh` if you have many machines.

The `/opt/sre` tree must contain `lab/`, `lib/`, `graphics/`, `translations/`, `locale/`, `bin/`, `sbin/`, `src/`, `venv/`. Lab authors also browse `src/` while writing `srelab.py` files. See [Runtime & Internals](internals.md) for the expected layout.

If you'd rather build in a separate working checkout (CI runner, personal dev tree) and move the result over afterwards, `rsync` or bind-mount the built tree into `/opt/sre` once `make install` has finished, then continue with the [Post-install steps](#post-install-steps).

## Debian package

On Debian 13 (trixie) and 14 (forky) SRE can be installed from Debian packages instead of a checkout: `python3-kathara` (the SRE fork of Kathara as a Python library), `sysreseval`, `sysreseval-podman` (the Podman engine, for a host without Docker) and `sysreseval-doc`, plus `python3-fs` on forky (rebuilt from the trixie source package, since forky dropped it). Every other dependency is a Debian package. The packages are served by the apt repository of the project on GitHub Pages (signed; `<dist>` is `trixie` or `forky`):

```bash
sudo curl -fsSL -o /usr/share/keyrings/sysreseval-archive-keyring.gpg https://sysreseval.github.io/sysreseval/apt/sysreseval-archive-keyring.gpg
sudo curl -fsSL -o /etc/apt/sources.list.d/sysreseval.sources https://sysreseval.github.io/sysreseval/apt/sysreseval-<dist>.sources
sudo apt update && sudo apt install sysreseval
```

The same `.deb` files are attached to each [GitHub release](https://github.com/sysreseval/sysreseval/releases): `apt install ./python3-kathara_*.deb ./sysreseval_*.deb` installs them with their dependencies without the repository.

**Without Docker.** `sudo apt install sysreseval-podman` installs SRE with the Podman engine: `podman` and what the engine needs, the switch of its networks, and the setup of the host, run when the package is installed (`sysreseval-podman-setup`; see [Podman engine](#podman-engine-rootless-containers)). No Docker package comes with it: in `sysreseval`, Docker, its command, `python3-kathara` and `python3-docker` are each an alternative to `podman` and to `sysreseval-podman` itself, so a plain `apt install sysreseval` still brings Docker, and a host that has Docker keeps it. Then set `container_engine = "podman"` in `/etc/sysreseval/params.py`. Until then every `sre` command of such a host ends with one line saying that Kathara is not installed and what to set.

The package follows the FHS instead of the `/opt/sre` tree:

| Path | Content |
|---|---|
| `/usr/sbin/sre`, `/usr/bin/sysreseval`, `/usr/bin/sre-wrapper` | the CLI, the GUI, the wrapper (`sudo /usr/sbin/sre --user`) |
| `/usr/bin/strip-instructor`, `/usr/bin/pin-question-hashes`, `/usr/bin/*-sre-translations` | the lab-authoring tools |
| `/usr/sbin/sysreseval-network-plugin` | `make network-plugin` of a checkout (`scripts/network-plugin.sh`) |
| `/usr/sbin/sysreseval-podman-setup`, `/usr/lib/sysreseval/bin/sre-vde-switch`, `/usr/lib/sysctl.d/60-sysreseval-podman.conf` | package `sysreseval-podman`: `make podman-setup` and `make vde-switch` of a checkout, the key quota of the machines running systemd |
| `/usr/lib/sysreseval/` | the Python code (`src/`), `lib/` readable by the `sre` user only |
| `/usr/share/sysreseval/lab/sre/` | the labs of the project, linked as `/var/lib/sre/lab/sre` |
| `/var/lib/sre/` | projects, archives, `exam.json`, `home/` (the directories shared with the machines), `lab/` (the site's own labs next to the `sre` link) |
| `/etc/sysreseval/params.py` | the site parameters (a conffile) |
| `/etc/sudoers.d/sysreseval`, `/usr/lib/sysctl.d/60-sysreseval.conf`, the `.desktop` file, the bash completion, `sysreseval-preload-images.service` (disabled) | the per-host bits of the list above |

`params.py` is not edited on a packaged host: `/etc/sysreseval/params.py` (Python syntax) sets the site's values of any parameter (`admin_gids`, `terminal_cmd_prefix`, `allow_privileged_machines`, `archive_dirs`, `sre_user_public_dir`...). It is executed after the base parameters and before the derived ones, so a changed `sre_pub_dir` moves the projects, archives and labs with it. The `sre` system user is created with a dynamic uid unless it exists already (create it beforehand with a fixed uid when `/var/lib/sre` or the archives are shared over NFS); its uid, gid and the `docker` gid are read from the accounts at run time. `sre update` is disabled on a packaged host (apt updates it), `apt purge` keeps `/var/lib/sre` and the user. `sysreseval-network-plugin` still has to be run once per Docker host for the labs with switch types, and the X server must accept TCP connections (post-install steps 2 below).

**Releasing.** `scripts/release.sh 0.13.2` (or `make release VERSION=0.13.2`) asks to confirm the version and the uncommitted leftovers, asks for release notes (one item per line; `-m` / `--notes-file` give them, `--yes` skips the questions), sets `sre_version` in `params.py`, adds the `0.13.2-1` entry to `debian/changelog` with the notes as its bullets, runs the unit tests, commits `Release 0.13.2` (notes in the body), tags `0.13.2`, pushes, creates the GitHub release with the notes followed by the generated list of commits, then waits for the two workflows: `release.yml` builds the trixie and forky packages and attaches them to the release, `pages.yml` deploys GitHub Pages with the documentation of `docs/` and the apt repository rebuilt by `scripts/apt-repo.sh` from the packages of every release (nothing binary is kept in git). Once per repository, `scripts/release.sh --setup` generates the signing key of the repository (with `gpg`, in your keyring), stores it as the secret `APT_SIGNING_KEY` and switches GitHub Pages to the Actions deployment.

**Building the packages by hand.** `scripts/build-deb.sh --dist trixie --ref 0.12.0 --test-install` builds the packages of the release tagged `0.12.0` in a `debian:trixie` container (Docker on the build host, which may be a Mac or a CI runner), checks them with lintian and installs them in a second container where it exercises `sre` (`sre list` through the link, `sre check` of a shipped lab, a student running `sre-wrapper`, the purge), then in a third one as a host without Docker (`sysreseval-podman` and no Docker nor Kathara package: the switch program, the one-line error while the engine is still Kathara, `sre list` and `sre check` once it is Podman). The switch is compiled during the package build from the archive of vde-2 the script downloads on the build host and puts in the sources (a package build has no network). `--local` packages the working tree instead (`make deb DIST=forky`); `--arch arm64` builds for that architecture; the result is in `build/deb/<dist>/`. The packaging lives in `debian/` (sysreseval), `packaging/kathara/` (the overlay applied to the fork tarball at the commit of `pin.sh`) and `packaging/python-fs/` (the forky rebuild). `debian/rules` sets `install_layout = "fhs"` and the version in the installed `params.py`; the unit tests of the repository run during the build unless `DEB_BUILD_OPTIONS=nocheck` (`--no-check`). The GitHub workflow `.github/workflows/release.yml` runs the script for trixie and forky on every tag and attaches the `.deb` files to the release.

## Updating

`sudo sre update` refreshes an installed tree from the GitHub repository: the latest release by default, `--main` for the head of `main`, `--check` to only see whether a newer version exists. It downloads the sources, merges `src/SRE/params.py` with the site's settings (customised parameters are kept; the questions concern only the parameters both customised here and changed upstream), replaces the files, keeps the site's own labs (everything in `lab/` but `lab/sre/`) and extra `lib/` files, rebuilds `bin/sre-wrapper`, keeps `bin/sre-vde-switch` (the switch of the Podman engine, built on the host; the update says when its recipe changed and it has to be built again with `make vde-switch FORCE=1`) and records the installed commit in `<main_sre_dir>/.sre-update.json`. See the [CLI reference](cli.md) for the details.

Before it replaces anything it runs `sre wipe`: run it outside class hours, every running project is stopped. It must run on the host that owns the tree: the NFS server in the read-only export topology (a host that can run no project skips the wipe, and `sre wipe` has to be run on the client hosts: a host without Docker daemon, or, where the engine is Podman, a host the setup script never prepared), and every workstation of the "replicate per workstation" topology. The per-host bits listed above are not touched; when the templates of `scripts/etc/` changed, the update says so and they have to be reinstalled by hand. The venv is rebuilt only with `--venv` (or `make venv` afterwards; the update says when the recipe changed). To go back to the previous version: `sudo sre update --ref <previous commit>`, printed at the end of each update. The sample labs of `lab/sre/` are reinstalled in full at every update.

## Running the installer

```bash
sudo ./scripts/install.sh
```

The script is interactive. It asks, in order:

| Prompt | Default | Purpose |
|--------|---------|---------|
| container engine | `kathara` (or what `params.py` says already) | `kathara`: Docker containers wired by Kathara. `podman`: rootless Podman containers of the `sre` user, on a host that needs no Docker. Asked first: the packages checked and installed depend on it. |
| `main_sre_dir` | `/opt/sre` if the script is at `/opt/sre/scripts/`, otherwise the script's parent directory | Runtime root for SRE binaries, libs, labs, graphics, translations, locale. Substituted for `/opt/sre` in the sudoers rule, `.desktop` file, and systemd unit at install time. |
| `sre` UID | `1100` | UID of the system user that owns running labs. |
| `sre` GID | `1100` | GID of the matching group. |
| `sre_pub_dir` | `/var/lib/sre` | Public state: running projects, archives, `exam.json`. |
| `sre_user_public_dir` | `/home/sre` | Per-lab shared `/home/sre/{running_lab}` mounts. |
| `allow_privileged_machines` | `y` | Whether `srelab.py` files may declare privileged containers. |
| `execute_commands_on_host` | `shell` | `shell`, `split`, or `False` — controls how lab `host_cmd()` calls are executed. |
| extra authorized src dirs | `/home` | Extra directories (beyond `main_sre_dir + '/lab'`, which is always included) from which `srelab.py` files may be loaded. Type `-` for none to restrict loading to the lab directory only. |
| Admin UIDs / GIDs | _(none)_ | Extra UIDs/GIDs that SRE treats as administrators. |

With the Kathara engine the Docker socket GID is detected automatically (no prompt). With the Podman engine there is no socket: `docker_gid`, the group the `sre` command runs with, is set to the group of the `sre` user.

After you confirm the summary, the installer:

1. Saves a backup of `params.py` to `params.py.bak.<YYYYmmdd-HHMMSS>`.
2. Patches the answers into `src/SRE/params.py` (single-line `key = value` substitutions, each verified after the edit).
3. Runs `make remove-debug-mode` if `debug_mode = True` is currently set — `make install` refuses to build while debug mode is on.
4. Creates the `sre` system group and user (`nologin` shell, home `/home/sre`) if they don't already exist. If a user/group with the requested name exists with a different UID/GID, it is **kept as-is** rather than overwritten — the installer warns and continues.
5. Adds `sre` to the Docker group resolved from the socket GID (Kathara engine only).
6. Installs `/etc/sudoers.d/sre` (**required** — the `sysreseval` GUI shells out to `sudo /opt/sre/sbin/sre --user` via `sre-wrapper`, so labs cannot start without this rule), validated by `visudo -c` before being kept. The rule it installs is:
   ```
   Defaults!/opt/sre/sbin/sre env_keep += "USER_USERNAME SRE_XAUTH_COOKIE"
   ALL  ALL= NOPASSWD: /opt/sre/sbin/sre --user *
   ```
   The rule grants passwordless access to every user on the host, not a specific group — `sre-wrapper` is the only entry point and it always passes `--user` with the caller's real login, so widening the sudoers scope doesn't lower the security envelope. `sre` enforces this itself: a `--user` call is accepted only when sudo ran `sre` directly (`SUDO_COMMAND`) and the compiled `sre-wrapper` binary is an ancestor of the process (`/proc/<pid>/exe`), so the C binary built by `make sre-wrapper` is required and a script cannot stand in for it. Restrict it to a specific group (e.g. `%etudiant`) if your site policy requires it.
7. Optionally installs `scripts/etc/sysreseval.desktop` to `/usr/share/applications/` so the GUI appears in the desktop application menu.
8. Optionally installs `scripts/etc/sre_bash_completion` to `/etc/bash_completion.d/sre` so the `sre` CLI gets bash completion system-wide.
9. Optionally installs the `sre-preload-images.service` systemd unit (oneshot, requires `opt-sre.mount`; not enabled by default — enable with `systemctl enable --now sre-preload-images.service` once `/opt/sre` is mounted), then the `sre-wipe-at-shutdown.service` unit (`sre wipe` when the machine halts; not enabled by default either — see [Stopping the projects when the machine halts](#6-stopping-the-projects-when-the-machine-halts)).
10. Optionally installs `scripts/etc/sre-inotify.conf` to `/etc/sysctl.d/60-sre-inotify.conf` and runs `sysctl --system`, raising the kernel inotify limits that privileged labs (systemd PID 1 in each container) would otherwise exhaust.
11. Runs `make venv` then `make install` (which is `check-debug-mode` + `sre-wrapper` + `wrappers`), then, by engine: offers `make network-plugin` (Kathara), or runs `make vde-switch` and `make podman-setup` (Podman: the switch of the networks, then the host itself, see [Podman engine](#podman-engine-rootless-containers)). Either may be run again later.
12. Optionally creates symlinks in `/usr/local/bin/` and `/usr/local/sbin/` pointing to each executable under `main_sre_dir/bin/` and `main_sre_dir/sbin/`, so `sre`, `sysreseval`, and `sre-wrapper` can be launched without their full path. Existing non-symlink files at the same paths are left untouched (with a warning).

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

6. **(Optional) Install the image pre-pull systemd unit** from `scripts/etc/sre-preload-images.service` into `/etc/systemd/system/`. It requires `opt-sre.mount` and is not enabled by default — see [Pre-loading Docker images](#5-pre-loading-docker-images) below. The unit `scripts/etc/sre-wipe-at-shutdown.service` is installed the same way — see [Stopping the projects when the machine halts](#6-stopping-the-projects-when-the-machine-halts).

7. **(Recommended) Raise the kernel inotify limits.** Privileged labs run `/sbin/init` (systemd PID 1) inside each container, and systemd reserves inotify watches per cgroup. Debian defaults (`max_user_instances = 128`) are quickly exhausted once two privileged labs run side by side, after which systemd in any new container exits at startup with `Failed to create control group inotify object: Too many open files`. Drop in the file shipped under `scripts/etc/` and apply it:
   ```bash
   install -m 0644 scripts/etc/sre-inotify.conf /etc/sysctl.d/60-sre-inotify.conf
   sysctl --system
   ```

8. **(Optional) Install bash completion** for the `sre` CLI. The script under `scripts/etc/sre_bash_completion` completes subcommands, running lab names (read from `/var/lib/sre/projects/`), available labs (via `sre list`), and option arguments. 
Install it system-wide:
   ```bash
   cp scripts/etc/sre_bash_completion /etc/bash_completion.d/sre
   ```
   Or source it per-user from `~/.bashrc`:
   ```bash
   . /path/to/sre_bash_completion
   ```

9. **Build the venv and the binaries:**
   ```bash
   make venv      # creates venv/ with Python 3.13 deps — see Dependencies below
   make install   # check-debug-mode + sre-wrapper + wrappers
   ```

10. **(For labs with switches) Install the network plugin with the switch types:** `make network-plugin` — see [Network plugin for the switch types](#network-plugin-for-the-switch-types). Labs whose networks are all hubs do not need it.

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

(Optional) Tune `src/SRE/params.py` further — see [Runtime & Internals](internals.md).

### 2. Enable X11 access for lab virtual machines

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

### 3. Restricting student access to Docker

For an exam to be meaningful, students must not be able to talk to Docker directly — otherwise a `docker exec -it ...` from a regular shell would let them connect to a forbidden container and bypass the lab's restrictions.

The recommended setup:

1. Remove students from the `docker` group entirely. Only `sre` (and any administrator account) should be a member.
2. Create a separate `docker-access` group and add the student accounts to it.
3. Toggle that group's access to `/var/run/docker.sock` with the two helpers shipped under `scripts/`:
   - `scripts/docker-allowed` grants `rw` on the socket to `docker-access` (run before non-exam sessions).
   - `scripts/docker-forbidden` revokes it (run before an exam).

Both helpers use `setfacl` on the Docker socket, so the change is immediate and survives until the next call.

### 4. Sharing evaluation archives for `sre watch`

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

### 5. Pre-loading Docker images

When an exam starts, every workstation pulls the same images at the same time — without precaution this can saturate the network and cause a meltdown. The fix is to pre-pull the images on each host ahead of time.

The unit `scripts/etc/sre-preload-images.service` (offered for installation by `scripts/install.sh`) runs once at boot and shells out to:

```
/opt/sre/sbin/sre preload-images --random-delay 120 /opt/sre/lab/
```

The `--random-delay` spreads the pulls over a 120-second window so workstations don't hit Docker Hub simultaneously. The unit requires `opt-sre.mount` (i.e. `/opt/sre` mounted as a systemd mount unit) and is **not enabled by default**:

```bash
systemctl enable --now sre-preload-images.service
```

On the pool hosts of the web front-end the random delay is not needed: the agent of each host runs the same command when the portal gives it its turn, and the portal lets only a few hosts download at the same time (`[preload] at_start = true` in `agent.toml`, `[pool] max_preloads` in `web.toml`; see *Pre-loading the images* in the [web front-end](web.md) page). Leave the unit disabled on such a host: both would pull.

### 6. Stopping the projects when the machine halts

No project survives a halt or a reboot: its containers die with Docker and its directory stays behind as a project that nothing runs. A workstation that is powered off every night (a cron job, a student pressing the button) should therefore go down with no project left, and no container still running while the system powers off.

The unit `scripts/etc/sre-wipe-at-shutdown.service` (offered for installation by `scripts/install.sh`) does nothing at boot and runs this when the machine goes down:

```
/opt/sre/sbin/sre wipe
```

It is ordered after `docker.service` and `remote-fs.target` (and, on a host prepared for the Podman engine, after the user manager of the `sre` account) and requires the mount of `/opt/sre`, so that the wipe runs while the engine and the network file systems are still there, and before the agent of the web front-end, which is therefore stopped first: on a pool host the agent closes the web projects itself, with their last evaluation, and the unit removes what is left (the projects of the Qt GUI, those the agent could not close in time). Stopping the unit by hand wipes too. It is **not enabled by default**:

```bash
systemctl enable --now sre-wipe-at-shutdown.service
```

## Reference

### Build targets

| Target | Output |
|--------|--------|
| `make wrappers` | Marks `sbin/sre` and `bin/sysreseval` shell wrappers executable. Refuses to build while `params.debug_mode = True`. |
| `make sre-wrapper` | `bin/sre-wrapper` (small C helper that escalates via `sudo`). |
| `make install` | `check-debug-mode` + `sre-wrapper` + `wrappers`. |
| `make network-plugin` | Kathara VDE network plugin with the switch types, built from the fork and installed in place of the stock plugin (see [Network plugin for the switch types](#network-plugin-for-the-switch-types)). |
| `make podman-setup` | Prepares the host for the Podman engine, as root: subordinate uids of the `sre` account, its user manager and the resource controllers of its machines, the directory of the engine, and on a host without Docker the address the machines reach the host at (see [Podman engine](#podman-engine-rootless-containers)). |
| `make vde-switch` | `bin/sre-vde-switch`: the switch of the Podman engine for the networks of mode `switch` and `managed`, the `vde_switch` of the Kathara network plugin built from a pinned, checksummed archive (see [Podman engine](#podman-engine-rootless-containers)). |
| `make translations` | Compile Qt `.ts → .qm` and gettext `.po → .mo`. |
| `make docs` | API docs (pdoc) + main docs (Sphinx) → `docs/html/main/`, `docs/html/api/`, `docs/documentation.pdf`. |
| `make set-debug-mode` / `make remove-debug-mode` | Flip `debug_mode` in `src/SRE/params.py`. |

`debug_mode` must be `False` for `make wrappers` and `make install`, but **must be `True`** to run exam-mode integration tests — the GUI then emits the JSON event stream those tests assert on.

### Tests

```bash
make tests                          # every test under tests/, the functional and web tests included (excludes test_exam_mode.py and test_exam_mode_web.py, scripts, and the Docker tests of make docker-tests)
make test FILE=test_net_config.py   # single file
make functional-tests               # functional tests (test_functional.py)
make exam-tests                     # exam-mode integration tests (requires debug_mode=True)
make web-exam-tests                 # the same GUI following an exam of the web site: exam.json written by the web agent on the portal's orders (requires debug_mode=True and the web dependencies; thirteen scenarios, about fourteen minutes)
make docker-tests                   # the Docker integration tests, left out of make tests and run by make all-tests (root, real containers: start/stop, save/restore, every lab of lab/sre/ from 0 to all its points with its `final` state, the connection log's database on a MariaDB container)
make podman-tests                   # the same on a host whose engine is Podman (root, real containers: the life of a project checked on Podman, then the labs of lab/sre/), left out of make tests and of make all-tests
make all-tests                      # tests + docker-tests + exam-tests + web-exam-tests
```

The two exam series start the GUI as `EXAM_USER`, and the GUI is single-instance per user (a GUI that starts ends the one already running for that user): run them one after the other, never at the same time on a machine, and not while that user works with the GUI there. A series refuses to start beside another GUI of that user, which it names, and says so when its own GUI was ended by one started meanwhile; it ends the GUIs it starts, and the one an earlier interrupted series may have left.

`make web-exam-tests` (`tests/test_exam_mode_web.py`) is the end-to-end series of the exams the web site puts on machines of the pool (see *On the workstations* in the [web server](web.md) chapter). Like `make exam-tests` it runs `sysreseval --debug` as a normal user (`EXAM_USER`, `etudiant` by default) on a temporary `SRE_PUB_DIR` with the mock `sre-wrapper`, as root; but nothing writes `exam.json` by hand: the web agent of the tree does (`PUT` / `DELETE /v1/exam`), driven by the portal's own code — the registry of the exams, a pool polling that agent and the reconciler of the machines, without the HTTP server nor the database. The thirteen scenarios (`SCENARIO=2`, `SCENARIOS="1 3"`):

| | Scenario |
|---|---|
| 1 | the lock a delay before the start, waiting → active → ended, the end screen and the release |
| 2 | minutes granted on the end screen resume the exam; the final evaluation is then run by the agent |
| 3 | *End now* and *Close* for the machine; a closed machine stays closed |
| 4 | a file set by hand is refused and left alone, then the machine is taken once it is free |
| 5 | a lab added during the exam |
| 6 | a student logging in after the start: the clock of the machine, the end by the duration |
| 7 | minutes added, then taken, for the machine during the exam |
| 8 | the start brought forward, postponed (the machine given back), then *Start now* |
| 9 | a machine unselected and selected again (a fresh run); the exam deleted without closing |
| 10 | a release delay of 0: the machine closed at the end |
| 11 | the student logs out and in again, while waiting then during the exam |
| 12 | a project of another lab stopped at the pre-start; a lab added while waiting |
| 13 | hybrid: a student of the audience logged in at the machine takes the exam there |

Every scenario of `make exam-tests` has its counterpart there (the end by the duration, another project stopped at the pre-start, the GUI restarted, the labs changed, time added after the end); the others are what only the web site does.

The lab test (`tests/test_docker_labs.py`, part of `make docker-tests` and `make podman-tests`) runs the labs the students open. Two environment variables turn it into a campaign over other labs or over both engines: `SRE_TEST_LABS=_DRAFT_misc` runs the lab files of that sub-directory of `lab/sre/` instead, and `SRE_TEST_LAB_RESULTS=<file>` appends one JSON line per lab to the file (the grade elements of the untouched project and of the project after `final`, the errors the commands logged, the time of each step, the engine and the host). With a results file the procedure of a lab goes to its end before the test fails, so that the line is complete; the verdict is the same. One lab alone: `pytest "tests/test_docker_labs.py::test_final_state_gives_every_point[dhcp.py]"`.

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

### Network plugin for the switch types

A lab may give each network a type of switch (`'mode': 'hub'`, `'switch'` or `'managed'` in its `_network_specs`, see [Hubs, switches and VLANs](switches.md)). Hubs — the default, and the only type of every lab written before — work with the stock Kathara network plugin, the one Kathara downloads by itself on the first start. The two other types need the VDE plugin of the fork `emotchane/NetworkPlugin` (branch `main`), installed under the name Kathara uses (`kathara/katharanp_vde:<arch>`):

```bash
make network-plugin      # as root or a member of the docker group
```

The target installs the plugin **in place of the stock one** and enables it. It first tries the published build, `sysreseval/katharanp_vde:<arch>` on Docker Hub (`NETWORK_PLUGIN_IMAGE`), downloaded under the name Kathara uses; when that one is not available, or with `BUILD=1`, it clones the fork into `build/` and builds the plugin for the architecture of the host (a few minutes; needs `git`, `python3` and Docker with `buildx`). It does nothing when the installed plugin already knows the switch types (`FORCE=1` installs it again) and refuses to run while a Kathara network exists: stop the running projects first (`sre wipe`). The plugin belongs to Docker, not to the SRE tree: it is installed once per host and stays when SRE is reinstalled. `scripts/install.sh` offers to run the target.

To publish a build (maintainers), from a clone of the fork on a host of the wanted architecture, in a terminal, after `docker login` with an account allowed to push to the organisation:

```bash
cd NetworkPlugin/vde
make push_amd64 PLUGIN_NAME=sysreseval/katharanp_vde     # builds sysreseval/katharanp_vde:amd64 and pushes it
```

A plugin that knows the switch types says so in its settings:

```bash
docker plugin inspect kathara/katharanp_vde:amd64 --format '{{.Settings.Env}}'   # ... KATHARA_SWITCH_MODES=hub,switch,managed
```

Without it `sre start` of a lab that uses a switch fails — Kathara's message (*the Kathara Network Plugin ... does not support it*) followed by the networks concerned and a reminder of `make network-plugin` — and nothing is left running. The management console of a managed switch is a unix socket the plugin gives to the group of `/var/run/docker.sock`: the `sre` user reaches it as it reaches Docker.

### Podman engine (rootless containers)

By default the machines of a lab are Docker containers started through Kathara, and the root of a machine is root on the host. With the **Podman engine** they are rootless Podman containers of the `sre` account: the root of a machine is an unprivileged uid of the host (one of the *subordinate* uids of the account, a different range for each running project), the networks are VDE hubs and switches run by SRE itself, and neither the Docker daemon nor Kathara takes part.

The engine is chosen in `params.py`, for the whole site or host by host:

```python
container_engine = "kathara"            # the engine of the site: "kathara" or "podman"
container_engine_by_host = {"s17": "podman", "s18": "podman"}   # the hosts that differ
```

A host is looked up by the name it gives itself (`hostname`), then by that name cut at its first dot. The second parameter is what lets one `params.py`, shared by every workstation of a room, put a few of them on Podman first. An unknown engine name, in either parameter, ends every `sre` command with a message naming the parameter.

**Every command works with the Podman engine, and every lab starts: hubs, switches and managed switches with their console, machines with an outside interface, privileged machines, saved projects (a save file is the same with both engines).** For the students and for the web site the commands, the pages and `info.json` are the same; what a machine is differs in a few places, listed under *What differs from Docker* below.

A host is prepared once, as root. With the Debian packages, `apt install sysreseval-podman` does it. `scripts/install.sh` does it when asked for the Podman engine. By hand, on a checkout:

```bash
apt install podman uidmap vdeplug passt catatonit dbus-user-session
make vde-switch              # scripts/vde-switch-build.sh; once for a tree several hosts share
make podman-setup            # scripts/podman-setup.sh (sysreseval-podman-setup of the package)
```

The host needs no Docker: neither the daemon, nor Kathara, nor the Docker SDK of Python. The units of SRE (the web agent, the preload of the images) start without `docker.service`, which they only *want*. A host may also keep its Docker and use the Podman engine; each host uses one engine.

`make vde-switch` builds `bin/sre-vde-switch`, the program behind the networks of mode `switch` and `managed` (`vde_switch_program` in `params.py`). It is the switch of the Kathara network plugin: vde-2 at the commit the plugin pins, with the plugin's one change, a frame buffer of 16 kB instead of 1.5 kB, so that a switch carries the 9000-byte frames a hub carries. The build takes a few seconds and needs `curl`, `cmake` and a C compiler; the archive is checked against its SHA-256 (`scripts/vde-switch-build.sh --fetch FILE` downloads it only, and `VDE_ARCHIVE=FILE` builds from it without network: what the Debian package build does). Without that program a lab with a switch is refused, with a line saying how to get it (the `make` target on a checkout, the package otherwise). A site may name another `vde_switch` in `vde_switch_program`; the one of Debian's `vde-switch` package works but loses every frame above 1518 bytes. `passt` (the `pasta` program) is needed by the labs that have a machine with an outside interface, and only by them.

The setup script reads `sre_user`, `podman_dir` and `podman_uid_ranges` in `params.py` (or `PODMAN_USER`, `PODMAN_DIR`, `PODMAN_UID_RANGES` in its environment) and changes nothing when run again:

- it gives the account a range of subordinate uids and gids in `/etc/subuid` and `/etc/subgid`, large enough for `podman_uid_ranges` projects (32 by default: this is how many projects a host runs at once, `sre start` refusing the next one), starting at 20000000 or above the ranges other accounts already have (`PODMAN_SUBID_FIRST` to choose);
- it starts the systemd user manager of the account at boot (`loginctl enable-linger`): the hubs and the switches of the networks are units of that manager, so they outlive the `sre` command that started them and are stopped with their project, and that manager makes the user namespace of Podman again after each boot (see below);
- it gives that user manager every resource controller for its machines (`/etc/systemd/system/user@<uid>.service.d/10-sre-podman.conf`: `Delegate=cpu cpuset io memory pids`, where systemd hands `cpu memory pids` to a user): a Kubernetes node (k3s) does not start without `cpuset`. A user manager reads this when it starts: the script restarts it when it runs nothing of SRE, and says that the change waits for the next boot when projects are running;
- it creates `podman_dir` (`/var/lib/sre/podman` by default; a local disk, never NFS), which holds the configuration of the engine (`config/containers/containers.conf`) and its image store. A registry mirror goes in `config/containers/registries.conf`, written by the administrator;
- it creates the user namespace of the account and checks that Podman answers with the group the `sre` command runs with (`docker_gid`), and that the user manager runs a unit;
- it raises the quota of kernel keys of a user (`/etc/sysctl.d/60-sre-podman.conf` on a checkout, a file of the package otherwise). Each service of a machine running systemd uses a key, counted against the uid of the root of the machine, which is an ordinary uid of the host: the default quota of 200 keys stops a project at a couple of dozen such machines;
- it orders the services of SRE installed on the host after the user manager of the account, with a drop-in each (`/etc/systemd/system/<unit>.d/10-sre-podman.conf`: `Wants=` and `After=user@<uid>.service`): the web agent, the wipe at shutdown and the preload of the images. Their unit files only know Docker, and at a shutdown they must stop, evaluate and wipe the projects while the machines still run (checked by rebooting a host: the web agent closes its projects with their last evaluation, then the wipe unit removes what is left, and only then does the user manager of the account stop; after the boot nothing is left and a lab starts). `PODMAN_ORDERED_UNITS` names other units, or none when empty; run the script again after installing one of those services;
- on a host without Docker it installs and starts `sre-host-address.service`, which gives the host the address the machines reach it at (`sre_host_ip`, 172.17.0.1: the one Docker's bridge has where Docker runs) on an interface of its own, `sre-host`, with a /32 that adds no route. The unit does nothing when another interface has the address by the time it starts, and the script removes it once Docker is installed. `PODMAN_HOST_ADDRESS=yes` installs it on a host that has a Docker which does not use that address, `PODMAN_HOST_ADDRESS=no` never does (the administrator gives the host the address).
- on a host that has the AppArmor profile of `tcpdump` (`/etc/apparmor.d/usr.bin.tcpdump`, from the package `tcpdump`), it adds two lines to the site file of that profile, `/etc/apparmor.d/local/usr.bin.tcpdump`, and has the profile loaded again when AppArmor is on: `signal (receive) peer=crun,` and `signal (receive) peer=runc,` (see *AppArmor* below). A line the file already names is left as it is, even commented out: that is how to decline one.

It ends by saying what the engine would refuse on the host: a lab with a switch when the switch program is missing, a lab with an outside interface when `pasta` is missing or when no interface of the host has the address `sre_host_ip`; and it says so when the parameters of the host still choose the other engine.

The images of the labs are downloaded into the store of the engine, which is not Docker's: `sre preload-images` fills it, and a missing image is pulled by `sre start` (the progress of that download is not shown). **What a uid range costs.** Each running project has a uid range of its own, and rootless Podman keeps one copy of the files of an image per range (the owners shifted). The copy is made the first time a project of that range uses the image, and kept. A host that runs one project at a time only ever uses the first range; the second range is used when two projects run at once, and so on. Measured:

| Filesystem of `podman_dir` | First start in a new range | Disk per range and image |
|---|---|---|
| btrfs (the copy shares its blocks) | about 4.5 s more for a lab on two images | about 180 MiB for the two |
| ext4 (a real copy) | 55 to 85 s more for a lab on `base13` alone | the size of the image: 2.2 GiB for `base13` |

On ext4 that is the price of every image for every range that comes into use: put `podman_dir` on btrfs or on XFS (both share the blocks of a copy), or lower `podman_uid_ranges` to the number of projects the host really runs at once. The copies also have their own place in the page cache: four projects of `dhcp.py` at once use the same anonymous memory with both engines (about 55 MiB each), but with Podman each of them also keeps 190 to 340 MiB of file pages for its copy, which the kernel gives back under pressure and which the web agent counts in the usage of the project (1100 MiB for the four, against 425 MiB with Docker).

**Privileges.** With Docker, the commands of a lab that has privileged machines keep root: Kathara refuses such a machine to anyone else, and the states and the grades of the lab then run with root's effective uid. With the Podman engine no lab needs that: every command of the engine becomes the `sre` account by itself, so a lab with privileged machines is handled like any other, and **the code of a lab never runs with the rights of root**. `sre start`, `restore`, `connect`, `exec`, `state` and `eval` drop root for good before the states and the grade of the lab run; `sre save` raises root only to open its output file and to read the files of the project, not around the `save` state of the lab. What still runs as root is SRE's own: the entry checks, the removal of the directories of a project (`sre stop`, `sre wipe`), handing the restored files to their student, `sre update`. A start that fails after its machines wrote into `shared/` or a volume removes those files through the user namespace of the account, where it is their root.

Nothing else of `params.py` changes on a Podman host: the `sre` command still drops to `sre_uid` and `docker_gid`. Rootless Podman keeps one user namespace per account, made by its first command after a boot, and `newuidmap` only makes it for a process whose group is the primary group of the account, which `docker_gid` usually is not; the engine therefore has the user manager of the account make the namespace when it is missing, and every command then joins it whatever its group.

While the `sre` account is a member of the `docker` group, what runs as that account can still reach the Docker daemon (the script says so). On a host that only uses the Podman engine, take the account out of that group and set `docker_gid` to its own group: nothing of the engine then has access to Docker.

#### What differs from Docker

**Networks.** A hub is the hub of vdeplug4, a switch or a managed switch is a `vde_switch` as with the Kathara network plugin, with the same console: `sre connect <switch>`, `sre exec`, `switch_cmd()` in a state and `test_switch()` in a grade give the same outputs and the same error codes. The links are much faster than those of the plugin (several Gbit/s, where the plugin gives some 50 Mbit/s): a lab that counts on an unshaped link being slow sees a difference.

**Privileged machines.** `privileged: True` gives a machine every capability *inside its own namespaces*, a writable `/proc/sys` and, when its entrypoint is an init, a real systemd (`systemctl`, the journal, the units of the image). It gives nothing of the host: the root of the machine is an ordinary uid, so there is no host device, no kernel log (`dmesg`), no kernel setting outside the network namespace (`kernel.*`), no module loaded with `modprobe`, no eBPF program, and `/sys` is read-only but for the control groups. Nested containers work (Docker, Compose and Vagrant's Docker provider in the `devops13` image). `sre start` returns once systemd is up in such a machine, a few seconds after its start, so the `initial` state of a lab can use `systemctl` at once.

**The outside interface.** A `bridged` machine gets, after its lab interfaces, an interface made by pasta that looks like Docker's bridge from inside: the address 172.17.0.2/16, `default via 172.17.0.1`, IPv4 only, an MTU of 1500. The host answers at `sre_host_ip` (172.17.0.1: the X11 displays of the `x11_host` machines, a capture a student sends to the host), and its services bound to its loopback only do not. That address must be one of the host's own: it is Docker's bridge where Docker runs, and the interface `sre-host` the setup script makes on a host without Docker; `sre start` refuses a lab with an outside interface until an interface of the host has it. What is not as with Docker:

- every bridged machine has the same address, so two of them cannot reach each other through the outside network, and the host cannot open a connection to a machine except through a published port (`ports`, bound on every address of the host, as with Docker);
- pasta relays TCP, UDP and ping: a `traceroute` beyond the machine shows nothing;
- the connections of a machine reach the services of the host and the Internet from an address of the host, as sockets of the `sre` account, not from 172.17.0.x: a rule a site wrote for `docker0` (to cut the Internet during an exam, for instance) does not see them.

**Files.** What a machine writes in `shared/` or in a volume belongs to a subordinate uid of the account, not to root (a setuid file left there gives nothing on the host), and a machine cannot read a file a student left there with mode 600. A save records, for each file and directory of `shared/` and of the volumes that a machine owns, its owner as the machines see it; a restore gives it to the same user of the new machines (other uids of the host: the new project has a uid range of its own) and puts the saved modes back, so a machine reads again the mode-600 file it had written and writes again in the directory it had made. The other files go back to the student. A restore with Docker does the same with the ids of the host, which are those of its machines: a file of the root of a machine is root's again, a file of `www-data` belongs to uid 33 again.

**Saved projects.** `sre save` and `sre restore` work as with Docker, and a save file is the same with both engines: a project saved on a Docker host restores on a Podman host and the reverse, so a web pool may have hosts of both. On a Podman host:

- a restore builds no image: the files of a machine are put back, and those it had deleted removed, in the new machine before its first process (a machine running systemd boots with the units that were enabled when it was saved);
- the shared directory and the volumes of a machine are not files of the machine: its archive holds nothing of them (they travel in the save file apart, as with Docker), and a restore leaves alone whatever an archive holds at those places;
- `sre save --full-images` is refused, and so is the restore of a file saved that way on a Docker host;
- a project one of whose machines is stopped is not saved (the message names the machine); Docker saves it;
- a save made on a Docker host that holds a device node, or a file owned by an id above 65535, is not restored: a rootless machine can make neither. The restore names the machine and the file, and leaves nothing behind;
- in a machine running systemd the journal (`/var/log/journal`) is a temporary filesystem and is not saved.

**Changing the engine of a host.** Do it when the host runs no project (`sre wipe` first): `sre stop` and `sre wipe` act on the engine `params.py` gives the host now, and the machines the other engine still runs would be left, without their project.

**The labs on both engines.** The 8 labs of `lab/sre` and the 60 drafts of `lab/sre/_DRAFT_misc` were run with Docker and with Podman on the same hosts and with the very same images (the store of Podman filled from the Docker daemon, image id for image id), from an untouched project to their `final` state, and every grade element of both evaluations compared (`tests/test_docker_labs.py` with `SRE_TEST_LABS` and `SRE_TEST_LAB_RESULTS`, see *Tests*). **66 of the 68 labs give the same result with both engines, element by element.** The two that do not:

- `nfs.py` (34 of 64 with Podman): the NFS server of the kernel cannot be started in a rootless machine;
- `quic.py` (86 of 107 with Podman): nginx does not start with `quic_bpf on`, which loads an eBPF program; the four elements of that server are lost.

`kubernetes.py` gets every point with both since the setup script hands the `cpuset` controller down to the machines. Six drafts give an untouched project a point or more (`ipv6.py`, `lan-attacks.py`, `openvpn.py`, `tcp.py`, `vlan.py`, `wireguard.py`): the same elements and the same points with both engines. The two labs that allow saving keep, after a save and a restore, the same elements with both engines and across them (`dhcp.py` all of them; `traceroute.py` loses the same ten in the four combinations: its `restore` state does not redo what `final` did).

The states and the evaluations take the same time with both engines. `sre start` takes longer with Podman when the lab has machines running systemd (about 7 s: the command returns once systemd is up, where Docker returns at once) and, a little, for the other labs (1021 s against 576 s for the 68 starts).

**AppArmor.** A host with AppArmor on needs nothing more. The machines run under the label of the container runtime (`crun`, or `runc`), a profile of the distribution that confines nothing, and what the labs ask of the kernel gets the same answers as on a host without AppArmor. Checked on a Debian 13 host installed from the packages, AppArmor enforcing, without Docker: 65 probes in a plain machine and in a machine running systemd, the tests of the engine, the 8 labs of `lab/sre` and 15 of the drafts that ask the most of the kernel (a nested Docker, k3s, managed switches, IPsec, WireGuard, NFQUEUE, MPLS, VXLAN, Open vSwitch) give there what they give on a host without AppArmor.

One thing follows from that label. A program of a machine whose path has a profile on the host runs under that profile, in the machine as on the host. The package `tcpdump` of Debian brings one (`/etc/apparmor.d/usr.bin.tcpdump`): under it `tcpdump` reads and writes capture files named `*.pcap` or `*.cap` and files of the home directory or of `/tmp`, nothing else (`tcpdump -w /srv/x.data`: `Permission denied`), and it takes signals from unconfined processes only. For AppArmor the processes of a machine are not unconfined, they carry the label of the runtime: `timeout 5 tcpdump …` then never ends and `kill` does nothing (Ctrl-C in a terminal works: that signal comes from the kernel). This is why the setup script adds its two lines to the site file of that profile. A profile another package of the host brings for a program the labs run in their machines would need the same lines in its own site file (on the test host only `tcpdump` and `man` had one).

### Dependencies

Installed by `make venv`:

| Package | Purpose |
|---------|---------|
| `kathara` | Docker lab orchestration — installed from the fork `emotchane/Kathara`, branch `main`, which adds `save_lab()` / `restore_lab()` (used by `sre save` / `sre restore`) and the switch modes of the collision domains (hub / switch / managed switch with VLANs, used by the `mode` of a network); `git` must be available when running `make venv` |
| `cryptography` | AES-GCM encryption of save files for labs that define `save_key` |
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
