#!/usr/bin/env python3
"""
Capture an 'ssh -vvv' trace, normalize and compare it.
"""

import argparse
import difflib
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

SSH_OPTS = ["-N", "-F", "none",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "IdentityFile=none", "-o", "IdentityAgent=none",
            "-o", "PubkeyAuthentication=no", "-o", "BatchMode=yes"]

RULES = [
    (r"\r\n?",                       "\n"),           # CRLF (raw tty)
    (r"[ \t]+$",                     ""),             # trailing whitespaces
    (r"/home/[^/\s]+/",              "/home/USER/"),  # home directory
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "HOST"),         # IPv4
    (r"\[[0-9a-fA-F:]+\]",           "[HOST]"),       # IPv6 in brackets
    (r"\B::1\b",                     "HOST"),         # plain ::1
    (r"(HOST\]?):\d+",               r"\1:PORT"),     # HOST:port, [HOST]:port
    (r"\bport \d+",                  "port PORT"),    # 'port 22'
    (r"-p \d+",                      "-p PORT"),      # '-p 22'
]

def body(text):
    return [line for line in text.splitlines(keepends=True) if not line.startswith("#")]

def sanitize(text):
    for pattern, repl in RULES:
        text = re.sub(pattern, repl, text, flags=re.MULTILINE)
    return text

_epilog = """\
examples:
  %(prog)s 127.0.0.1 2222 > live.txt                just capture
  %(prog)s 127.0.0.1 2222 -d debian.txt             capture and compare
  %(prog)s -d debian.txt live.txt                   just compare two files
  %(prog)s -d debian.txt live.txt --html > d.html   the same as a HTML page
"""

def main():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", nargs="?", help="server to capture (login user is always 'user')")
    parser.add_argument("port", nargs="?", help="server port")
    parser.add_argument("-d", "--diff", metavar="FILE", nargs="+", default=[], type=Path,
                        help="compare against specified file or two files")
    parser.add_argument("--html", action="store_true",
                        help="write the comparison as a side-by-side HTML page")
    args = parser.parse_args()

    if len(args.diff) > 2:
        parser.error("--diff takes one or two files")
    if args.html and not args.diff:
        parser.error("--html needs something to compare, use it with --diff")
    for f in args.diff:
        if not f.is_file(): parser.error(f"File not found: {f}")
    if len(args.diff) == 2 and (args.host or args.port):
        parser.error("--diff with two files compares those - drop host and port")
    if len(args.diff) < 2 and not (args.host and args.port):
        parser.error("host and port are required to capture")

    if len(args.diff) == 2:
        # Compare two existing traces
        ref, new = args.diff
        trace, name = sanitize(new.read_text(encoding="utf-8")), str(new)
    else:
        # Capture trace to server
        ref, name = (args.diff[0] if args.diff else None), "captured"
        cmd = ["ssh", "-vvv", *SSH_OPTS, "-p", args.port, f"user@{args.host}"]
        trace = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True).stdout
        # Add some header comment lines
        header = [f"# label: ",
                  f"# captured: {date.today()}",
                  f"# " + " ".join(cmd)]
        trace = sanitize("\n".join(header) + "\n" + trace)

    if ref is None:
        sys.stdout.write(trace)
        return 0

    old = body(sanitize(ref.read_text(encoding="utf-8")))
    delta = list(difflib.unified_diff(old, body(trace), str(ref), name))
    if args.html:
        sys.stdout.write(difflib.HtmlDiff(wrapcolumn=100).make_file(
            old, body(trace), str(ref), name))
    else:
        sys.stdout.writelines(delta)
    return 1 if delta else 0


if __name__ == "__main__":
    raise SystemExit(main())
