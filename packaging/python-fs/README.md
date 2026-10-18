# python3-fs for forky

The Kathara fork needs PyFilesystem2 (`import fs`), which Debian removed from unstable and testing
in January 2026 (`python-fs`, request #1082581: dead upstream). trixie still ships
`python3-fs 2.4.16-7`, patched to need neither `pkg_resources` nor `appdirs` nor `six` at runtime.

On a release without `python3-fs`, `scripts/build-deb.sh` rebuilds the trixie source package for
it (`python3-fs_2.4.16-7~forky1_all.deb`):

```
echo 'deb-src http://deb.debian.org/debian trixie main' > /etc/apt/sources.list.d/trixie-src.list
apt-get update
apt-get source --only-source python-fs/trixie
cd python-fs-2.4.16
dch --local '~forky' --distribution forky --force-distribution 'Rebuild of the trixie package for forky.'
DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -us -uc -b
```

The unit tests are skipped: they fail with Python 3.14 (#1123243). The script copies every
`*.patch` file of `patches/` into `debian/patches/` of the source package and appends it to its
`series` (quilt patches on the sources as left by Debian's own patches):

- `platformdirs-no-upper-bound.patch`: Debian's `platformdirs.patch` requires `platformdirs~=4.3.6`,
  which `dh_python3` turns into `python3-platformdirs (<< 4.4)`, uninstallable on forky (4.10).
