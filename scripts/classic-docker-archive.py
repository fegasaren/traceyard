#!/usr/bin/env python3
"""Normalize docker save (including Docker 29 hybrid output) to Docker archive.

The result contains manifest.json, a content-addressed config, and uncompressed
layer.tar entries only. OCI layout/index/blob paths are never copied through.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


def member(archive, name):
    info = archive.getmember(name)
    if not info.isfile():
        raise ValueError(f"Archive member is not a regular file: {name}")
    return archive.extractfile(info)


def small_json(archive, name):
    with member(archive, name) as source:
        content = source.read(8 * 1024 * 1024 + 1)
    if len(content) > 8 * 1024 * 1024:
        raise ValueError(f"Image metadata is too large: {name}")
    return content, json.loads(content)


def add_bytes(archive, name, data):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), 0o644, 0
    archive.addfile(info, io.BytesIO(data))


def layer_file(source_archive, source_name, destination):
    with member(source_archive, source_name) as source:
        magic = source.read(4)
    with member(source_archive, source_name) as source, destination.open("wb") as output:
        if magic[:2] == b"\x1f\x8b":
            with gzip.GzipFile(fileobj=source) as decompressed:
                shutil.copyfileobj(decompressed, output, 1024 * 1024)
        elif magic == b"\x28\xb5\x2f\xfd":
            try:
                from compression import zstd
            except ImportError:
                if not shutil.which("zstd"):
                    raise ValueError("A zstd layer needs Python 3.14+ or the zstd command on the build host") from None
                compressed = destination.with_suffix(".zst")
                try:
                    with compressed.open("wb") as temporary:
                        shutil.copyfileobj(source, temporary, 1024 * 1024)
                    subprocess.run(["zstd", "--decompress", "--stdout", "--quiet", str(compressed)], stdout=output, check=True)
                finally:
                    compressed.unlink(missing_ok=True)
            else:
                with zstd.ZstdFile(source) as decompressed:
                    shutil.copyfileobj(decompressed, output, 1024 * 1024)
        else:
            shutil.copyfileobj(source, output, 1024 * 1024)
    # Reject a still-compressed or malformed layer before publishing the archive.
    with tarfile.open(destination, "r:") as contents:
        for _ in contents:
            pass
    with destination.open("rb") as content:
        return "sha256:" + hashlib.file_digest(content, "sha256").hexdigest()


def convert(source, destination, tag):
    with tarfile.open(source, "r:*") as original:
        _, manifests = small_json(original, "manifest.json")
        matching = [item for item in manifests if tag in (item.get("RepoTags") or [])]
        if len(matching) != 1:
            raise ValueError("docker save must contain exactly one image with the requested tag")
        image = matching[0]
        config_bytes, config = small_json(original, image["Config"])
        layers = image["Layers"]
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        if (not isinstance(layers, list) or len(layers) != len(diff_ids)
                or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) for digest in diff_ids)):
            raise ValueError("Image configuration and layer list disagree")
        config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
        layer_names = [digest.removeprefix("sha256:") + "/layer.tar" for digest in diff_ids]
        manifest = [{"Config": config_name, "RepoTags": [tag], "Layers": layer_names}]
        written = set()
        created = False
        try:
            with tempfile.TemporaryDirectory(prefix=".classic-layers-", dir=destination.parent) as temporary:
                output = destination.open("xb")
                created = True
                with output, gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as classic:
                        add_bytes(classic, "manifest.json", json.dumps(manifest, separators=(",", ":")).encode())
                        add_bytes(classic, config_name, config_bytes)
                        for index, (source_name, target_name, expected) in enumerate(zip(layers, layer_names, diff_ids)):
                            path = Path(temporary) / f"{index}.tar"
                            actual = layer_file(original, source_name, path)
                            if actual != expected:
                                raise ValueError(f"Layer {index} does not match its configuration diff_id")
                            if target_name not in written:
                                info = tarfile.TarInfo(target_name)
                                info.size, info.mode, info.mtime = path.stat().st_size, 0o644, 0
                                with path.open("rb") as content:
                                    classic.addfile(info, content)
                                written.add(target_name)
                            path.unlink()
        except Exception:
            if created:
                destination.unlink(missing_ok=True)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve() or args.destination.exists():
        parser.error("destination must be a new file distinct from the input archive")
    try:
        convert(args.source, args.destination, args.tag)
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Docker archive conversion failed: {exc}\n")


if __name__ == "__main__":
    main()
