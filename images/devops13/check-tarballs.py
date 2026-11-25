"""check-tarballs.py DIR ARCH: every DIR/*.tar is a `docker save` archive holding one tagged image
of the architecture ARCH (run at build time by images/devops13/Dockerfile, removed after)."""
import glob
import json
import sys
import tarfile


def main(directory: str, arch: str) -> int:
    files = sorted(glob.glob(f"{directory}/*.tar"))
    if not files:
        print(f"no image tarball in {directory}")
        return 1
    for path in files:
        with tarfile.open(path) as tar:
            manifest = json.load(tar.extractfile("manifest.json"))[0]
            config = json.load(tar.extractfile(manifest["Config"]))
        tags = manifest.get("RepoTags") or []
        if not tags:
            print(f"{path}: no tag")
            return 1
        if config.get("architecture") != arch:
            print(f"{path}: {config.get('architecture')} is not {arch}")
            return 1
        print(path, ' '.join(tags), config.get("architecture"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
