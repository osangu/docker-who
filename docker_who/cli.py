"""Small CLI around the attribution engine and Docker request observer."""

import argparse
import os
import signal
import sys
import time
from pathlib import Path

from . import __version__
from .attribution import (
    PROC_ROOT,
    STATE_FILE,
    Containers,
    Resolver,
    State,
    container_of,
    read_comm,
)
from .docker_observer import DockerObserver, scan_docker_clis


def positive_pid(value):
    try:
        pid = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("PID must be a positive integer") from None
    if pid <= 0:
        raise argparse.ArgumentTypeError("PID must be a positive integer")
    return pid


def show_processes(pids, state, containers):
    resolver = Resolver(state, containers)
    print(f"{'PID':>8}  {'USER':<24} {'EVIDENCE':<14} {'CONTAINER':<24} COMMAND")
    for pid in pids:
        user, evidence = resolver.resolve(pid)
        cid = container_of(pid)
        name = containers.name(cid) if cid else "-"
        print(f"{pid:>8}  {user:<24} {evidence:<14} {name:<24} {read_comm(pid)}")


def _exit_on_signal(signum, frame):
    raise SystemExit(0)


def watch(state, containers):
    Path(state.path).parent.mkdir(parents=True, exist_ok=True)
    state.prune(containers)
    scan_docker_clis(state, containers)
    observer = DockerObserver(state, containers)
    signal.signal(signal.SIGTERM, _exit_on_signal)
    observer.start()
    print(f"docker-who: recording attribution in {state.path}", flush=True)
    try:
        while True:
            observer.housekeep(unresolved=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="docker-who",
        description="Identify the local users behind Docker containers and exec sessions.",
    )
    parser.add_argument("--version", action="version", version=f"docker-who {__version__}")
    parser.add_argument("--state-file", default=STATE_FILE,
                        help="attribution state file (default: %(default)s)")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("watch", help="observe local Docker start/restart/exec requests")
    commands.add_parser("ps", help="list Docker processes with user attribution")
    resolve = commands.add_parser("resolve", help="resolve one or more host PIDs")
    resolve.add_argument("pids", nargs="+", type=positive_pid, metavar="PID")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return
    if sys.platform != "linux":
        parser.error("process attribution requires a Linux host; Docker Desktop is not supported")

    state = State(args.state_file)
    containers = Containers()
    try:
        if args.command == "watch":
            watch(state, containers)
        else:
            pids = args.pids if args.command == "resolve" else sorted(
                int(entry) for entry in os.listdir(PROC_ROOT)
                if entry.isdigit() and container_of(int(entry)) is not None
            )
            show_processes(pids, state, containers)
    except OSError as error:
        parser.error(str(error))
