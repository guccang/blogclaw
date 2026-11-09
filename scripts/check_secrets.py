#!/usr/bin/env python3
"""Check the Git index for local secret files and recognizable API keys.

Only filenames, line numbers and rule names are reported, never matched values.
This focused guard is not a full secret audit and does not scan Git history.
"""

import json
import re
import subprocess
import sys
from pathlib import PurePosixPath


# 覆盖泄露文件中的长 sk- 密钥及旧式 JWT；测试中仅使用动态生成的假值。
SECRET_PATTERNS = (
    ("long sk- API key", re.compile(rb"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{40,}")),
    (
        "JWT credential",
        re.compile(rb"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\."
                   rb"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}"),
    ),
)


def is_local_secret_file(path):
    name = PurePosixPath(path).name
    if name == "audio-agent.json":
        return True
    return (name == ".env" or name.startswith(".env.")) and not name.endswith(".example")


def inspect_file(path, content):
    findings = []
    if is_local_secret_file(path):
        findings.append((path, None, "local secret configuration"))
    for rule, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            line = content.count(b"\n", 0, match.start()) + 1
            findings.append((path, line, rule))
    return findings


def git(*args, cwd=None):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def scan_index(cwd=None):
    # 扫描暂存区中的 blob，而不是可能被改回占位值的工作区文件。
    cwd = git("rev-parse", "--show-toplevel", cwd=cwd).rstrip(b"\n").decode(
        "utf-8", errors="surrogateescape")
    entries = git("ls-files", "--stage", "-z", "--full-name", cwd=cwd).split(b"\0")
    findings = []
    blobs = {}
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, sha, stage = metadata.split()
        if stage != b"0":
            raise ValueError("Resolve merge conflicts before checking secrets.")
        if mode == b"160000":  # 子模块没有本仓库中的文件 blob。
            continue
        if sha not in blobs:
            blobs[sha] = git("cat-file", "blob", sha.decode("ascii"), cwd=cwd)
        path = raw_path.decode("utf-8", errors="surrogateescape")
        findings.extend(inspect_file(path, blobs[sha]))
    return findings


def format_finding(finding):
    path, line, rule = finding
    # 转义特殊文件名，并防止密钥被放进文件名后出现在检查日志里。
    raw_path = path.encode("utf-8", errors="surrogateescape")
    for _, pattern in SECRET_PATTERNS:
        raw_path = pattern.sub(b"[REDACTED]", raw_path)
    safe_path = json.dumps(raw_path.decode("utf-8", errors="replace"), ensure_ascii=True)
    location = f"{safe_path}:{line}" if line is not None else safe_path
    return f"{location}: {rule}"


def main():
    try:
        findings = scan_index()
    except (OSError, subprocess.CalledProcessError, ValueError):
        print("Secret check could not read the Git index; check the repository and resolve conflicts.",
              file=sys.stderr)
        return 2
    if findings:
        print("Secret check failed (values redacted):", file=sys.stderr)
        for finding in findings:
            print(format_finding(finding), file=sys.stderr)
        print("Unstage local secrets and rotate any credentials already exposed.", file=sys.stderr)
        return 1
    print("Secret check passed for the Git index (not Git history).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
