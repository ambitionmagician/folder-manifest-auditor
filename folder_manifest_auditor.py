#!/usr/bin/env python3
"""Create and verify SHA-256 manifests for folder trees (Python 3.8+)."""

import argparse
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path


CHUNK_SIZE = 1024 * 1024
FORMAT = "folder-manifest-v1"
DIGEST = re.compile(r"[0-9a-f]{64}")


class AuditError(Exception):
    """The audit could not be completed reliably."""


def quoted(path):
    """Return a path as a single-line, JSON-quoted string."""
    return json.dumps(str(path), ensure_ascii=True)


def excluded(relative, patterns):
    """Return True if relative matches any glob pattern (case-sensitive)."""
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)


def fingerprint(info):
    """Tuple used to detect concurrent modification of a file."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def hash_file(path, initial):
    """Stream-hash a regular file and detect changes during reading."""
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if fingerprint(before) != fingerprint(initial):
            raise AuditError("file changed before hashing: " + quoted(path))
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            length += len(chunk)
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (length != before.st_size
            or fingerprint(before) != fingerprint(after)
            or fingerprint(initial) != fingerprint(after)):
        raise AuditError("file changed while hashing: " + quoted(path))
    return length, digest.hexdigest()


def scan(root, manifest_path, patterns, follow):
    """Walk the tree and return {relative_path: (size, sha256)}."""
    root_info = root.stat()
    if not stat.S_ISDIR(root_info.st_mode):
        raise AuditError("not a directory: " + quoted(root))

    records = {}
    # Each work item carries the identities of its real ancestor directories
    # so that symlink cycles are caught even when following links.
    stack = [(root, "", frozenset())]
    while stack:
        directory, prefix, ancestors = stack.pop()
        info = directory.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise AuditError("not a directory: " + quoted(directory))
        identity = (info.st_dev, info.st_ino)
        if identity in ancestors:
            raise AuditError("directory link cycle at " + quoted(directory))
        lineage = ancestors | {identity}
        with os.scandir(directory) as entries:
            for entry in entries:
                relative = prefix + entry.name
                if excluded(relative, patterns):
                    continue
                path = Path(entry.path)
                if path == manifest_path:
                    continue
                link_info = entry.stat(follow_symlinks=False)
                reparse = (
                    getattr(link_info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                )
                if not follow and (stat.S_ISLNK(link_info.st_mode) or reparse):
                    continue
                if follow and stat.S_ISLNK(link_info.st_mode):
                    # Skip symlinks that point at the manifest itself.
                    if path.resolve() == manifest_path:
                        continue
                current = entry.stat(follow_symlinks=True) if follow else link_info
                if stat.S_ISDIR(current.st_mode):
                    stack.append((path, relative + "/", lineage))
                elif stat.S_ISREG(current.st_mode):
                    records[relative] = hash_file(path, current)
    return records


def write_manifest(path, records):
    """Atomically write the manifest as pretty-printed JSON."""
    document = {
        "format": FORMAT,
        "files": [
            {"path": name, "size": records[name][0], "sha256": records[name][1]}
            for name in sorted(records)
        ],
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", newline="\n", dir=path.parent,
            prefix=".folder-manifest-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = stream.name
            json.dump(document, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def unique_keys(pairs):
    """json object_pairs_hook that rejects duplicate keys."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate JSON key: " + quoted(key))
        result[key] = value
    return result


def read_manifest(path):
    """Read and validate a manifest, returning {relative_path: (size, sha256)}."""
    if not stat.S_ISREG(path.stat().st_mode):
        raise AuditError("manifest is not a regular file: " + quoted(path))
    with path.open("r", encoding="utf-8-sig") as stream:
        doc = json.load(stream, object_pairs_hook=unique_keys)
    if (not isinstance(doc, dict)
            or set(doc) != {"format", "files"}
            or doc["format"] != FORMAT
            or not isinstance(doc["files"], list)):
        raise AuditError("invalid or unsupported manifest format")

    result = {}
    for index, record in enumerate(doc["files"]):
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
            raise AuditError("invalid fields in files[{}]".format(index))
        name, size, digest = record["path"], record["size"], record["sha256"]
        if (not isinstance(name, str)
                or "\0" in name
                or any(part in ("", ".", "..") for part in name.split("/"))
                or type(size) is not int
                or size < 0
                or not isinstance(digest, str)
                or not DIGEST.fullmatch(digest)):
            raise AuditError("invalid record in files[{}]".format(index))
        if name in result:
            raise AuditError("duplicate manifest path: " + quoted(name))
        # Manifest paths are comparison keys, never filesystem operands.
        result[name] = (size, digest)
    return result


def filter_expected(records, patterns):
    """Drop expected records whose paths are excluded by the given globs."""
    if not patterns:
        return records
    result = {}
    for name, record in records.items():
        parts = name.split("/")
        if not any(
            excluded("/".join(parts[:i]), patterns)
            for i in range(1, len(parts) + 1)
        ):
            result[name] = record
    return result


def compare(expected, actual, quiet):
    """Report differences and return 0 for a match, 1 otherwise."""
    counts = dict.fromkeys(
        ("missing", "extra", "size-changed", "hash-changed"), 0
    )
    for name in sorted(expected.keys() | actual.keys()):
        labels = []
        if name not in actual:
            labels.append("missing")
        elif name not in expected:
            labels.append("extra")
        else:
            if expected[name][0] != actual[name][0]:
                labels.append("size-changed")
            if expected[name][1] != actual[name][1]:
                labels.append("hash-changed")
        for label in labels:
            counts[label] += 1
        if labels and not quiet:
            print("{}: {}".format(", ".join(labels), quoted(name)))
    different = any(counts.values())
    if not quiet:
        print("{}: expected={} actual={} {}".format(
            "DIFFERENCES" if different else "MATCH",
            len(expected),
            len(actual),
            " ".join("{}={}".format(k, v) for k, v in counts.items()),
        ))
    return int(different)


def manifest_target(root, user_manifest):
    """Determine the absolute manifest path from the CLI arguments."""
    if user_manifest is None:
        target = root / "manifest.json"
    else:
        target = Path(user_manifest)
        if not target.is_absolute():
            target = Path.cwd() / target
    target = Path(os.path.abspath(target))
    if target.is_symlink():
        raise AuditError("manifest must not be a symlink: " + quoted(target))
    if target.exists():
        target = target.resolve(strict=True)
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for name, help_text in (
        ("make", "write a new manifest (replace if present)"),
        ("check", "verify a tree against a saved manifest"),
    ):
        sub = modes.add_parser(name, help=help_text, description=help_text)
        sub.add_argument("folder", type=Path, help="folder to audit")
        sub.add_argument(
            "--manifest", type=Path, metavar="FILE",
            help="manifest location (default: FOLDER/manifest.json)",
        )
        sub.add_argument(
            "--exclude", action="append", default=[], metavar="GLOB",
            help="omit matching root-relative paths (repeatable)",
        )
        sub.add_argument(
            "--follow-symlinks", action="store_true",
            help="include linked targets, even outside the folder",
        )
        sub.add_argument(
            "--quiet", action="store_true",
            help="suppress normal output; errors still go to stderr",
        )
    args = parser.parse_args(argv)

    try:
        root = args.folder.resolve(strict=True)
        target = manifest_target(root, args.manifest)

        if args.mode == "check":
            if not target.is_file():
                raise AuditError(
                    "manifest is not a regular file: " + quoted(target)
                )
            expected = filter_expected(read_manifest(target), args.exclude)
            actual = scan(root, target, args.exclude, args.follow_symlinks)
            return compare(expected, actual, args.quiet)

        # make
        if target.exists() and not target.is_file():
            raise AuditError(
                "manifest path is not a regular file: " + quoted(target)
            )
        if not target.parent.is_dir():
            raise AuditError(
                "manifest parent directory does not exist: " + quoted(target.parent)
            )
        records = scan(root, target, args.exclude, args.follow_symlinks)
        write_manifest(target, records)
        if not args.quiet:
            print("Wrote {} files to {}".format(len(records), quoted(target)))
        return 0

    except (AuditError, OSError, ValueError, RuntimeError, OverflowError) as exc:
        print("error: {}".format(str(exc)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
