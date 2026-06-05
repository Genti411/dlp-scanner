"""CLI: scan files (or stdin) for PII and optionally output a redacted copy.

  dlp scan  <path...>     report findings (counts by type + sensitivity)
  dlp redact <file>       print the file with PII masked

Exits non-zero when sensitive data is found, so it can gate a pipeline.
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

from .detectors import find_all
from .redact import redact

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def _iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for dirpath, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in files:
                    yield os.path.join(dirpath, name)
        else:
            yield p


def _read(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\x00" in raw:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="dlp", description="PII / DLP scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("paths", nargs="+")
    r = sub.add_parser("redact"); r.add_argument("file")
    args = p.parse_args(argv)

    if args.cmd == "redact":
        text = _read(args.file) or ""
        redacted, _ = redact(text)
        sys.stdout.write(redacted)
        return 0

    total = Counter()
    n_findings = 0
    for path in _iter_files(args.paths):
        text = _read(path)
        if text is None:
            continue
        findings = find_all(text)
        if findings:
            for f in findings:
                total[f.type] += 1
                n_findings += 1
            by_type = Counter(f.type for f in findings)
            print(f"{path}: " + ", ".join(f"{t}={c}" for t, c in by_type.items()))
    print(f"\n{n_findings} PII finding(s): " +
          (", ".join(f"{t}={c}" for t, c in total.items()) or "none"))
    return 1 if n_findings else 0


if __name__ == "__main__":
    sys.exit(main())
