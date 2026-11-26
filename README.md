# Folder Manifest Auditor — verify a folder tree against a hash manifest

CLI tool with two modes: 'make' writes a manifest.json for a folder tree (relative path, size, sha256 for every file, skipping symlinks); 'check' verifies a tree against an existing manifest and reports missing, extra, size-changed, and hash-changed files with a clear summary and exit code (0 = exact match, 1 = differences). Flags: --exclude GLOB (repeatable), --follow-symlinks off by default, --quiet. Standard library only; streams file hashing in chunks so multi-GB files are fine.
