"""Record who asks dockerd to start containers or exec into them.

bpftrace (docker_sock.bt) prints every "POST /" request written to the docker
socket together with the writer's uid and loginuid. Of those, three matter:

  POST /containers/<id|name>/start     container start  (docker run starts by ID)
  POST /containers/<id|name>/restart   container restart
  POST /exec/<exec_id>/start           exec: read <exec_id>.pid right away —
                                       containerd deletes it soon after the exec ends

Containers started before the exporter have no record. For those, running docker
CLI processes (docker exec -it / attach / start -a / run -it) are scanned at
observer startup and periodically as a fallback.
"""

import ctypes
import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path

from .attribution import (
    PROC_ROOT,
    TASK_DIR,
    Containers,
    State,
    container_of,
    exec_pid_files,
    person,
    read_comm,
    read_loginuid,
    read_stat,
    read_uid,
)

BPFTRACE = os.environ.get("BPFTRACE", "bpftrace")
DOCKER_SOCKETS = [
    path for path in os.environ.get("DOCKER_SOCKETS", "/var/run/docker.sock,/run/docker.sock").split(",") if path
]
SCRIPT = Path(__file__).with_name("docker_sock.bt")

REQUEST_RE = re.compile(
    r"^POST /(?:v[\d.]+/)?(?:containers/([^/?\s]+)/(start|restart)|exec/([0-9a-f]{64})/start)[?\s]"
)
EXEC_PID_WAIT_SECONDS = 3.0
CLI_SCAN_INTERVAL = 30.0
PRUNE_INTERVAL = 3600.0

CLK_TCK = os.sysconf("SC_CLK_TCK")
# docker global options that take a value, so their value is not the subcommand.
GLOBAL_VALUE_OPTIONS = {"-H", "--host", "-c", "--context", "--config", "-l", "--log-level",
                        "--tlscacert", "--tlscert", "--tlskey"}


def _boot_time() -> float:
    try:
        with open(f"{PROC_ROOT}/stat") as handle:
            for line in handle:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except OSError:
        pass
    return 0.0


def session_start(session: int, cid: str):
    """Earliest start time among a container's processes in a session, or None."""
    earliest = None
    for entry in os.listdir(PROC_ROOT):
        if not entry.isdigit():
            continue
        stat = read_stat(int(entry))
        if stat and stat[1] == session and container_of(int(entry)) == cid:
            earliest = stat[2] if earliest is None else min(earliest, stat[2])
    return earliest


def close_fd_function() -> str:
    """The kernel function close(2) goes through: renamed twice since 5.10."""
    for name in ("file_close_fd", "close_fd", "__close_fd"):
        try:
            listed = subprocess.run(
                [BPFTRACE, "-l", f"fentry:vmlinux:{name}"], capture_output=True, text=True, timeout=30
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            break
        if f"fentry:vmlinux:{name}" in listed.split():
            return name
    return "close_fd"


def _die_with_parent():
    # PR_SET_PDEATHSIG: take bpftrace down with the exporter.
    ctypes.CDLL(None).prctl(1, signal.SIGTERM)


def actor_of_pid(pid: int, uid: int | None = None, loginuid: int | None = None, comm: str | None = None) -> dict:
    return {
        "pid": pid,
        "uid": read_uid(pid) if uid is None else uid,
        "loginuid": read_loginuid(pid) if loginuid is None else loginuid,
        "comm": read_comm(pid) if comm is None else comm,
    }


class DockerObserver:
    def __init__(self, state: State, containers: Containers):
        self.state = state
        self.containers = containers
        self.up = False
        self._last_cli_scan = 0.0
        self._last_prune = 0.0
        self._housekeeping = threading.Lock()

    # --- bpftrace ---------------------------------------------------------------

    def program(self) -> str:
        match = " || ".join(
            f'strncmp($path, "{path}", {len(path) + 1}) == 0' for path in DOCKER_SOCKETS
        )
        return (
            SCRIPT.read_text()
            .replace("@@SOCKET_MATCH@@", match)
            .replace("@@CLOSE_FD@@", close_fd_function())
        )

    def start(self):
        threading.Thread(target=self._run, name="docker-observer", daemon=True).start()

    def _run(self):
        backoff = 10
        while True:
            started = time.time()
            try:
                self._watch()
            except OSError as error:
                print(f"docker observer: cannot run {BPFTRACE}: {error}", flush=True)
            self.up = False
            if time.time() - started > 300:
                backoff = 10
            print(f"docker observer: bpftrace exited, retrying in {backoff}s", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)

    def _watch(self):
        env = dict(os.environ, BPFTRACE_MAX_STRLEN="200")
        process = subprocess.Popen(
            [BPFTRACE, "-f", "json", "-B", "line", "-e", self.program()],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            preexec_fn=_die_with_parent,
        )
        try:
            for line in process.stdout:
                try:
                    message = json.loads(line)
                except ValueError:
                    # Module BTF needs CAP_SYS_ADMIN; only vmlinux BTF is used.
                    if "modules BTF" not in line:
                        print(f"bpftrace: {line.rstrip()}", flush=True)
                    continue
                if message.get("type") == "attached_probes":
                    self.up = True
                    print(f"docker observer: watching {', '.join(DOCKER_SOCKETS)}", flush=True)
                elif message.get("type") == "printf":
                    self.handle(message.get("data", ""))
        finally:
            process.kill()
            process.wait()

    # --- requests ---------------------------------------------------------------

    def handle(self, data: str):
        fields = data.split("\t", 4)
        if len(fields) != 5:
            return
        pid, uid, loginuid, comm, request = fields
        match = REQUEST_RE.match(request)
        if not match:
            return
        actor = {"pid": int(pid), "uid": int(uid), "loginuid": int(loginuid), "comm": comm}
        ref, action, exec_id = match.groups()
        if exec_id:
            threading.Thread(target=self._record_exec, args=(exec_id, actor), daemon=True).start()
        else:
            self._record_start(ref, action, actor)

    def _record_start(self, ref: str, action: str, actor: dict):
        cid = self.containers.resolve(ref, min_prefix=1)
        if cid is None:
            print(f"docker observer: {action} of unknown container {ref}", flush=True)
            return
        self.state.record_container(cid, actor, action, "ebpf")
        print(f"docker observer: {person(actor)} {action} {self.containers.name(cid)}", flush=True)

    def _record_exec(self, exec_id: str, actor: dict):
        deadline = time.time() + EXEC_PID_WAIT_SECONDS
        while time.time() < deadline:
            found = self._find_exec_pid(exec_id)
            if found:
                break
            time.sleep(0.05)
        else:
            print(f"docker observer: no pid file for exec {exec_id[:12]}", flush=True)
            return

        cid, pid = found
        stat = read_stat(pid)
        if stat:
            starttime = stat[2]
        else:
            # The exec root already exited (`sh -c 'python train.py &'`). Its children
            # keep its session ID; none of them can be older than the root.
            starttime = session_start(pid, cid)
            if starttime is None:
                return
        self.state.record_exec(cid, pid, starttime, exec_id, actor, "ebpf")
        print(f"docker observer: {person(actor)} exec {self.containers.name(cid)} (pid {pid})", flush=True)

    @staticmethod
    def _find_exec_pid(exec_id: str):
        try:
            cids = os.listdir(TASK_DIR)
        except OSError:
            return None
        for cid in cids:
            try:
                with open(f"{TASK_DIR}/{cid}/{exec_id}.pid") as handle:
                    return cid, int(handle.read().strip())
            except (OSError, ValueError):
                continue
        return None

    # --- housekeeping -----------------------------------------------------------

    def housekeep(self, unresolved: bool):
        """Called on every scrape. Cheap unless something is due."""
        if not self._housekeeping.acquire(blocking=False):
            return
        try:
            now = time.time()
            if unresolved and now - self._last_cli_scan > CLI_SCAN_INTERVAL:
                self._last_cli_scan = now
                scan_docker_clis(self.state, self.containers)
            if now - self._last_prune > PRUNE_INTERVAL:
                self._last_prune = now
                self.state.prune(self.containers)
        finally:
            self._housekeeping.release()


# --- running docker CLI processes ---------------------------------------------------


def _subcommand(args: list[str]):
    """('exec', [rest...]) from docker's argv after the binary, or None."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in GLOBAL_VALUE_OPTIONS:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        if arg == "container" and index + 1 < len(args):
            return args[index + 1], args[index + 2 :]
        return arg, args[index + 1 :]
    return None


def _option_value(args: list[str], name: str):
    for index, arg in enumerate(args):
        if arg == name and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None


def scan_docker_clis(state: State, containers: Containers) -> int:
    """Record containers/execs that a running docker CLI is attached to. Returns how many."""
    recorded = 0
    boot = None
    for entry in os.listdir(PROC_ROOT):
        if not entry.isdigit() or read_comm(int(entry)) != "docker":
            continue
        pid = int(entry)
        try:
            with open(f"{PROC_ROOT}/{pid}/cmdline", "rb") as handle:
                argv = [part.decode(errors="replace") for part in handle.read().split(b"\0") if part]
        except OSError:
            continue
        parsed = _subcommand(argv[1:])
        stat = read_stat(pid)
        if not parsed or not stat:
            continue
        command, rest = parsed
        if command not in ("exec", "attach", "start", "restart", "run"):
            continue

        actor = actor_of_pid(pid, comm="docker")
        if command == "run":
            name = _option_value(rest, "--name")
            if name:
                cid = containers.resolve(name)
            else:
                boot = _boot_time() if boot is None else boot
                started = boot + stat[2] / CLK_TCK
                near = [
                    cid
                    for cid in containers.ids()
                    if (info := containers.info(cid)) and started - 1 <= info["created"] <= started + 15
                ]
                cid = near[0] if len(near) == 1 else None
        else:
            cid = next(
                (found for token in rest if not token.startswith("-")
                 and (found := containers.resolve(token, min_prefix=4))),
                None,
            )
        if not cid:
            continue

        if command == "exec":
            # The exec this CLI started is the one whose process began closest to it.
            best = None
            for exec_id, exec_pid in exec_pid_files(cid).items():
                exec_stat = read_stat(exec_pid)
                if exec_stat and abs(exec_stat[2] - stat[2]) <= 5 * CLK_TCK:
                    distance = abs(exec_stat[2] - stat[2])
                    if best is None or distance < best[0]:
                        best = (distance, exec_id, exec_pid, exec_stat[2])
            if best and not state.has_exec(cid, best[2], best[3]):
                recorded += state.record_exec(cid, best[2], best[3], best[1], actor, "cli")
        else:
            recorded += state.record_container(cid, actor, command, "cli", replace=False)
    return recorded
