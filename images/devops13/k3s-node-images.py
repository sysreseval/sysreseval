"""k3s-node-images.py AIRGAP_TAR OUT_TAR REPOSITORY...: the images REPOSITORY... (rancher/mirrored-pause,
rancher/klipper-lb...) of the k3s air-gap archive AIRGAP_TAR (an OCI layout, uncompressed) written
into OUT_TAR, another OCI layout k3s imports the same way (run at build time by
images/devops13/Dockerfile, removed after).

The worker nodes of the Kubernetes lab import only these (the pause image of every pod, the
klipper-lb image of the ServiceLB pods every node runs, the busybox of the helper pods local-path
runs on the node of a new volume): the whole archive is ~200 MB of blobs that containerd unpacks
again on every node.  The blobs referenced by an index but absent from the
archive (the manifests of the other architectures) are left out, as they are in the archive.
"""
import io
import json
import sys
import tarfile

INDEX_TYPES = ('application/vnd.oci.image.index.v1+json',
               'application/vnd.docker.distribution.manifest.list.v2+json')


def blob_name(digest: str) -> str:
    algorithm, _, value = digest.partition(':')
    return f"blobs/{algorithm}/{value}"


def collect(tar: tarfile.TarFile, names: set, digest: str, found: list) -> bool:
    """Adds *digest* and what it references to *found*; False when it is absent from the archive."""
    name = blob_name(digest)
    if name not in names:
        return False
    found.append(name)
    document = json.load(tar.extractfile(name))
    if document.get('mediaType') in INDEX_TYPES or 'manifests' in document:
        children = [collect(tar, names, m['digest'], found) for m in document.get('manifests', [])]
        return any(children)
    for layer in [document['config']] + document.get('layers', []):
        if blob_name(layer['digest']) not in names:
            raise SystemExit(f"{name}: blob {layer['digest']} missing")
        found.append(blob_name(layer['digest']))
    return True


def main(source: str, target: str, repositories: list) -> int:
    with tarfile.open(source) as tar:
        names = set(tar.getnames())
        index = json.load(tar.extractfile('index.json'))
        manifest = json.load(tar.extractfile('manifest.json')) if 'manifest.json' in names else []
        entries, blobs = [], []
        for repository in repositories:
            prefix = f"docker.io/{repository}:"
            chosen = [m for m in index['manifests']
                      if m.get('annotations', {}).get('io.containerd.image.name', '').startswith(prefix)]
            if not chosen:
                print(f"{repository}: not in {source}")
                return 1
            for entry in chosen:
                if not collect(tar, names, entry['digest'], blobs):
                    print(f"{repository}: no blob of {entry['digest']}")
                    return 1
                entries.append(entry)
                print(entry['annotations']['io.containerd.image.name'])
        tags = [m for m in manifest if any(t.startswith(f"{r}:") for t in m.get('RepoTags', []) for r in repositories)]
        with tarfile.open(target, 'w') as out:
            def add(name: str, data: bytes) -> None:
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o644
                out.addfile(info, io.BytesIO(data))
            add('oci-layout', json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
            add('index.json', json.dumps({**index, 'manifests': entries}).encode())
            if tags:
                add('manifest.json', json.dumps(tags).encode())
            for name in dict.fromkeys(blobs):
                member = tar.getmember(name)
                out.addfile(member, tar.extractfile(member))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(__doc__.splitlines()[0])
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3:]))
