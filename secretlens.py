#!/usr/bin/env python3
"""Scan authorized local text files for common credential patterns."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

PATTERNS = [
    ("Private key block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("AWS access key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,100}\b")),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    ("JWT token", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Generic secret assignment", "review", re.compile(r"\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\"']?([A-Za-z0-9_\-/.]{16,})[\"']?", re.I)),
]
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}


def redact(value):
    if len(value) <= 8:
        return "[REDACTED]"
    return value[:4] + "•" * min(12, max(4, len(value) - 8)) + value[-4:]


def scan_text(text, file_name):
    findings = []
    for kind, severity, pattern in PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            column = match.start() - text.rfind("\n", 0, match.start())
            raw = match.group(0)
            shown = redact(raw)
            if "=" in raw or ":" in raw:
                shown = re.sub(r'([=:]\s*["\']?)([^"\'\s]+)(["\']?\s*)$', lambda m: m.group(1) + redact(m.group(2)) + m.group(3), raw)
            findings.append({"type": kind, "severity": severity, "file": file_name, "line": line, "column": column, "preview": shown})
    return findings


def candidate_files(root):
    if root.is_file():
        return [root]
    return [path for path in root.rglob("*") if path.is_file() and not any(part in SKIP_DIRS for part in path.parts)]


def scan(root, max_bytes):
    findings = []
    files_read = 0
    for path in candidate_files(root):
        try:
            if path.stat().st_size > max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_read += 1
        display_name = path.name if root.is_file() else str(path.relative_to(root))
        findings.extend(scan_text(text, display_name))
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "files_read": files_read, "summary": {"secrets_found": len(findings), "critical": sum(f["severity"] == "critical" for f in findings), "high": sum(f["severity"] == "high" for f in findings), "review": sum(f["severity"] == "review" for f in findings)}, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="authorized file or directory to scan")
    parser.add_argument("--output", type=Path, help="write JSON report to this path")
    parser.add_argument("--max-file-mb", type=float, default=2, help="skip files larger than this size (default: 2)")
    args = parser.parse_args()
    if not args.path.exists():
        parser.error(f"path does not exist: {args.path}")
    report = scan(args.path, int(args.max_file_mb * 1024 * 1024))
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
