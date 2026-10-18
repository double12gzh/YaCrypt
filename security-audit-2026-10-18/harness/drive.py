#!/usr/bin/env python3
"""Minimal pexpect driver for interactive YaCrypt commands (audit harness).

Usage:
  DRIVE_EXPECTS='regex1|response1;regex2|response2' python3 drive.py <timeout_sec> <cmd> [args...]

Each expect pattern is matched in order; the response is sent followed by a newline
(empty response = bare Enter). Full transcript is printed, ending with
DRIVE_EXIT=<exit code> or DRIVE_EXIT=SIGNAL:<n>.
"""
import os
import sys

import pexpect


def main() -> int:
    timeout = float(sys.argv[1])
    cmd = sys.argv[2:]
    child = pexpect.spawn(cmd[0], cmd[1:], timeout=timeout, encoding="utf-8",
                          codec_errors="replace")
    child.logfile_read = sys.stdout
    try:
        for spec in os.environ.get("DRIVE_EXPECTS", "").split(";"):
            if not spec:
                continue
            pat, _, resp = spec.partition("|")
            child.expect(pat)
            child.sendline(resp)
        child.expect(pexpect.EOF)
    except pexpect.TIMEOUT:
        sys.stdout.write("\nDRIVE_TIMEOUT waiting for pattern\n")
    try:
        child.close(force=True)
    except Exception:
        pass
    if child.signalstatus is not None:
        print(f"\nDRIVE_EXIT=SIGNAL:{child.signalstatus}")
        return 2
    print(f"\nDRIVE_EXIT={child.exitstatus}")
    return 0 if child.exitstatus == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
