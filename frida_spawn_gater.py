"""
frida_spawn_gater.py

Await a Windows process whose name or command line matches PATTERN, then
replace this script with an interactive frida session attached to that
process.

Example
=======
    ## Wait for any notepad.exe instance to start and attach with script.
    python frida_spawn_gater.py --timeout 30 notepad.exe -l agent.js
"""

from __future__ import annotations

import argparse
import itertools
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, NoReturn

try:
    import wmi  # type: ignore
except ImportError:
    sys.stderr.write("Missing dependencies: install with\n    pip install wmi\n")
    sys.exit(1)

__all__ = ["await_process", "main"]

log = logging.getLogger("spawn_gater")

_WATCHER_RETRY_DELAYS = (1, 2, 4, 8, 16, 30, 30, 30)
_SPINNER_CHARS = "-|/\\"


def _make_watcher(retries=_WATCHER_RETRY_DELAYS) -> Any | None:
    """Return a WMI process-creation watcher, retrying if the service is busy."""
    for delay in retries:
        try:
            return wmi.WMI().watch_for(
                notification_type="Creation",
                wmi_class="Win32_Process",
            )
        except wmi.x_wmi:
            time.sleep(delay)
    log.error("Unable to obtain a WMI watcher after several attempts.")
    return None


def _spinner() -> itertools.cycle[str]:
    """Endless cycle of spinner glyphs."""
    return itertools.cycle(_SPINNER_CHARS)


def _next_event(watcher, timeout_ms: int | None):
    """Block on *watcher* and swallow WMI timeout exceptions."""
    try:
        return watcher(timeout_ms=timeout_ms) if timeout_ms is not None else watcher()
    except wmi.x_wmi_timed_out:
        return None


def compile_pattern(raw: str, _max_len: int = 256) -> re.Pattern[str]:
    """
    Convert *raw* into a case-insensitive regex, escaping if invalid.
    """
    if len(raw) > _max_len:
        raise ValueError(
            f"Pattern exceeds {_max_len} characters; refine your match string."
        )
    try:
        return re.compile(raw, re.IGNORECASE)
    except re.error:
        log.warning("Pattern %r is not valid regex - treating literally.", raw)
        return re.compile(re.escape(raw), re.IGNORECASE)


def await_process(
    regex: re.Pattern[str],
    timeout: float | None = None,
) -> tuple[str, int] | None:
    """
    Block until a process whose name or command line matches *regex* spawns.

    Returns (image_name, pid) or None on timeout.
    """
    deadline = None if timeout is None else time.time() + timeout
    watcher = _make_watcher()
    if watcher is None:
        return None

    spin = _spinner()
    sys.stdout.write(next(spin))
    sys.stdout.flush()

    while True:
        if deadline and time.time() >= deadline:
            sys.stdout.write("\b \b")
            sys.stdout.flush()
            return None

        wait_ms = (
            None
            if deadline is None
            else max(0, int(min(deadline - time.time(), 1.0) * 1000))
        )
        evt = _next_event(watcher, wait_ms)

        if evt and regex.search(f"{evt.Caption or ''}\0{evt.CommandLine or ''}"):
            sys.stdout.write("\b \b")
            sys.stdout.flush()
            return (evt.Caption or "", int(evt.ProcessId))

        sys.stdout.write("\b" + next(spin))
        sys.stdout.flush()


def _exec_frida(pid: int, extra: list[str]) -> NoReturn:  # pragma: no cover
    """Run `frida -p PID` interactively and exit with the same status."""
    frida_cli = shutil.which("frida")
    if frida_cli is None:
        raise FileNotFoundError(
            "frida executable not found in PATH. Install Frida 17.2+ first."
        )

    argv = [frida_cli, "-p", str(pid), *extra]

    try:
        old_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:  # launched without a console
        old_handler = None
    try:
        rc = subprocess.call(argv, env=os.environ.copy())
    finally:
        if old_handler is not None:
            signal.signal(signal.SIGINT, old_handler)

    sys.exit(rc)


def parse_cli(argv: list[str]) -> tuple[re.Pattern[str], float | None, list[str], int]:
    """
    Return (compiled_pattern, timeout_seconds, frida_options, log_level).
    """
    parser = argparse.ArgumentParser(
        prog="frida_spawn_gater",
        description="Await a Windows process whose name or command line matches "
        "PATTERN, then attach Frida.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        metavar="SECS",
        help="abort if no match within SECS (exit 124)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="log_level",
        action="store_const",
        const=logging.WARNING,
        help="only warnings and errors",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="log_level",
        action="store_const",
        const=logging.DEBUG,
        help="debug output",
    )
    parser.set_defaults(log_level=logging.INFO)
    parser.add_argument("pattern", help="regex or literal to match the process")
    parser.add_argument(
        "frida_opts",
        nargs=argparse.REMAINDER,
        help="arguments passed verbatim to the frida CLI",
    )
    a = parser.parse_args(argv)
    return compile_pattern(a.pattern), a.timeout, a.frida_opts, a.log_level


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    regex, timeout, frida_opts, log_level = parse_cli(argv or sys.argv[1:])

    logging.basicConfig(level=log_level, format="%(message)s")

    log.info(
        "Waiting for process spawn matching %r ... (press Ctrl-C to cancel)",
        regex.pattern,
    )
    try:
        result = await_process(regex, timeout)
    except KeyboardInterrupt:
        sys.exit("\nCancelled by user.")

    if result is None:
        log.error("Timed out after %.1fs without a match.", timeout)
        sys.exit(124)

    name, pid = result
    log.info("Process %r (PID %d) spawned. Launching frida ...", name, pid)

    _exec_frida(pid, frida_opts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
