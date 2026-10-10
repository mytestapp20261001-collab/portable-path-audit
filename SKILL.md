---
name: portable-path-audit
description: Find filesystem entry names that create Windows and Unicode/case portability risks.
---

# Portable Path Audit

Use the public `audit(...)` API or the documented CLI for the scoped read-only check. Read README.md before interpreting a result. Require an explicitly chosen local input; do not broaden the scan to unrelated directories.

Only Python 3.12 standard-library dependencies are needed. The implementation reads local files/metadata with bounded inputs and no-follow filesystem traversal. Never execute input scripts, extract archives, repair inputs, upload reports, access credentials, or change permissions. A requested audit does not authorize any such follow-on action. Treat filenames, hashes, and metadata as potentially private; share reports only with the requesting user unless separately authorized.

Report exit 0 as no findings within the documented scope, exit 1 as findings to review, and exit 2 as incomplete/invalid input. Do not interpret a pass as general security, format-conformance, or portability certification. Run the example and unit-test commands in README.md when changing this tool.
