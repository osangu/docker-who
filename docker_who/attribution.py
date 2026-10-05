"""Resolve a host PID to the person behind it.

Host processes: loginuid (the ssh login, survives sudo), then for root processes
the owner of the logind session (user-<uid>.slice) or the systemd unit, then the
process uid.

Docker container processes have no loginuid and usually run as root, so the person
is whoever asked dockerd to start the container or exec into it. docker_observer.py
records those requests; here a process is matched to an exec by its session ID
(runc starts init and every exec in a new session, and the session survives the
exec root exiting and its children being reparented to init).

Docker metadata comes from read-only files, not docker.sock:
  <data-root>/containers/<id>/config.v2.json                 name, init PID
  /run/containerd/io.containerd.runtime.v2.task/moby/<id>/   <exec_id>.pid
"""

import json
import os
import pwd
import re
import threading
import time
from datetime import datetime

PROC_ROOT = os.environ.get("PROC_ROOT", "/proc")
CONTAINERS_DIR = os.environ.get("DOCKER_CONTAINERS_DIR", "/var/lib/docker/containers")
TASK_DIR = os.environ.get("CONTAINERD_TASK_DIR", "/run/containerd/io.containerd.runtime.v2.task/moby")
STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/docker-who/attribution.json")

UNSET_LOGINUID = 4294967295
# systemd cgroup driver: .../docker-<id>.scope, cgroupfs driver: /docker/<id>
CONTAINER_RE = re.compile(r"(?:docker-|/docker/)([0-9a-f]{64})(?:\.scope|/|$)", re.M)
SERVICE_RE = re.compile(r"/([^/\n]+)\.service(?:/|$)", re.M)
SESSION_OWNER_RE = re.compile(r"/user\.slice/user-(\d+)\.slice(?:/|$)", re.M)
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")

_uid_names: dict[int, str] = {}


# --- /proc -------------------------------------------------------------------


def read_stat(pid: int):
    """(ppid, session id, start time in clock ticks), or None if the PID is gone."""
    try:
        with open(f"{PROC_ROOT}/{pid}/stat") as handle:
            data = handle.read()
    except OSError:
        return None
    # comm may contain spaces and parentheses; fields resume after the last ')'.
    fields = data[data.rindex(")") + 2 :].split()
    return int(fields[1]), int(fields[3]), int(fields[19])


def read_cgroup(pid: int) -> str:
    try:
        with open(f"{PROC_ROOT}/{pid}/cgroup") as handle:
            return handle.read()
    except OSError:
        return ""


def container_of(pid: int):
    match = CONTAINER_RE.search(read_cgroup(pid))
    return match.group(1) if match else None


def read_loginuid(pid: int) -> int:
    try:
        with open(f"{PROC_ROOT}/{pid}/loginuid") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return UNSET_LOGINUID


def read_uid(pid: int):
    try:
        return os.stat(f"{PROC_ROOT}/{pid}").st_uid
    except OSError:
        return None


def read_comm(pid: int) -> str:
    try:
        with open(f"{PROC_ROOT}/{pid}/comm") as handle:
            return handle.read().strip()
    except OSError:
        return "unknown"


def username(uid: int) -> str:
    if uid not in _uid_names:
        try:
            _uid_names[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_names[uid] = f"uid-{uid}"
    return _uid_names[uid]


def person(actor: dict) -> str:
    """The login user behind a recorded docker request, else its uid."""
    loginuid = actor.get("loginuid", UNSET_LOGINUID)
    return username(actor["uid"] if loginuid == UNSET_LOGINUID else loginuid)


def live_sessions() -> set[int]:
    sessions = set()
    for entry in os.listdir(PROC_ROOT):
        if entry.isdigit():
            stat = read_stat(int(entry))
            if stat:
                sessions.add(stat[1])
    return sessions


# --- docker metadata -----------------------------------------------------------


def _parse_docker_time(value: str) -> float:
    # "2026-10-01T13:43:03.965138021Z": trim nanoseconds to what datetime accepts.
    match = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?", value or "")
    if not match:
        return 0.0
    fraction = (match.group(2) or ".0")[:7]
    return datetime.fromisoformat(match.group(1) + fraction + "+00:00").timestamp()


class Containers:
    """Container ID / name / init PID from config.v2.json, cached by mtime."""

    def __init__(self, root: str = CONTAINERS_DIR):
        self.root = root
        self._cache: dict[str, tuple[float, dict]] = {}

    def info(self, cid: str):
        path = f"{self.root}/{cid}/config.v2.json"
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            self._cache.pop(cid, None)
            return None
        cached = self._cache.get(cid)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            with open(path) as handle:
                config = json.load(handle)
        except (OSError, ValueError):
            return cached[1] if cached else None
        info = {
            "id": cid,
            "name": (config.get("Name") or "").lstrip("/") or cid[:12],
            "pid": (config.get("State") or {}).get("Pid") or 0,
            "created": _parse_docker_time(config.get("Created")),
        }
        self._cache[cid] = (mtime, info)
        return info

    def ids(self) -> list[str]:
        try:
            return [entry for entry in os.listdir(self.root) if CONTAINER_ID_RE.match(entry)]
        except OSError:
            return []

    def exists(self, cid: str) -> bool:
        return os.path.isdir(f"{self.root}/{cid}")

    def resolve(self, ref: str, min_prefix: int = 4):
        """Full ID for what the docker CLI sent: full ID, name, or unique ID prefix.

        min_prefix guards guesses from CLI argv, where a short token like "0" is
        more likely an option value than a container.
        """
        if CONTAINER_ID_RE.match(ref) and self.exists(ref):
            return ref
        ids = self.ids()
        for cid in ids:
            info = self.info(cid)
            if info and info["name"] == ref:
                return cid
        if len(ref) < min_prefix or not re.fullmatch(r"[0-9a-f]+", ref):
            return None
        matches = [cid for cid in ids if cid.startswith(ref)]
        return matches[0] if len(matches) == 1 else None

    def name(self, cid: str) -> str:
        info = self.info(cid)
        return info["name"] if info else cid[:12]


def exec_pid_files(cid: str) -> dict[str, int]:
    """{exec_id: host PID} for the execs containerd still tracks in a container."""
    found = {}
    try:
        entries = os.listdir(f"{TASK_DIR}/{cid}")
    except OSError:
        return found
    for entry in entries:
        if entry.endswith(".pid") and entry != "init.pid":
            try:
                with open(f"{TASK_DIR}/{cid}/{entry}") as handle:
                    found[entry[:-4]] = int(handle.read().strip())
            except (OSError, ValueError):
                continue
    return found


# --- recorded requests -----------------------------------------------------------


class State:
    """Who started each container / ran each exec, persisted across restarts.

    containers: {cid: {"actor", "action", "source", "at"}}
    execs:      {"cid:pid": {"exec_id", "starttime", "actor", "source", "at"}}
    actor:      {"pid", "uid", "loginuid", "comm"}
    source:     "ebpf" (seen on docker.sock) or "cli" (a running docker CLI process)
    """

    def __init__(self, path: str = STATE_FILE):
        self.path = path
        self.lock = threading.Lock()
        self.containers: dict[str, dict] = {}
        self.execs: dict[str, dict] = {}
        self.load()

    def load(self):
        try:
            with open(self.path) as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        self.containers = data.get("containers", {})
        self.execs = data.get("execs", {})

    def save(self):
        if not os.path.isdir(os.path.dirname(self.path) or "."):
            return
        # PID in the name: `--dump` run inside the container writes the same file.
        temporary = f"{self.path}.{os.getpid()}.tmp"
        try:
            with open(temporary, "w") as handle:
                json.dump({"containers": self.containers, "execs": self.execs}, handle, indent=1)
            os.replace(temporary, self.path)
        except OSError as error:
            print(f"cannot write {self.path}: {error}", flush=True)

    def record_container(self, cid: str, actor: dict, action: str, source: str, replace: bool = True):
        with self.lock:
            if not replace and cid in self.containers:
                return False
            self.containers[cid] = {"actor": actor, "action": action, "source": source, "at": time.time()}
            self.save()
            return True

    def record_exec(self, cid: str, pid: int, starttime: int, exec_id: str, actor: dict, source: str):
        key = f"{cid}:{pid}"
        with self.lock:
            existing = self.execs.get(key)
            if existing and existing["starttime"] == starttime and source == "cli":
                return False
            self.execs[key] = {
                "exec_id": exec_id,
                "starttime": starttime,
                "actor": actor,
                "source": source,
                "at": time.time(),
            }
            self.save()
            return True

    def container(self, cid: str):
        with self.lock:
            return self.containers.get(cid)

    def exec_for(self, cid: str, session: int):
        with self.lock:
            return self.execs.get(f"{cid}:{session}")

    def has_exec(self, cid: str, pid: int, starttime: int) -> bool:
        with self.lock:
            existing = self.execs.get(f"{cid}:{pid}")
            return bool(existing and existing["starttime"] == starttime)

    def prune(self, containers: Containers):
        """Forget containers that are gone and execs whose session has no process left."""
        sessions = live_sessions()
        with self.lock:
            before = (len(self.containers), len(self.execs))
            self.containers = {cid: r for cid, r in self.containers.items() if containers.exists(cid)}
            self.execs = {
                key: r
                for key, r in self.execs.items()
                if containers.exists(key.split(":")[0]) and int(key.split(":")[1]) in sessions
            }
            if (len(self.containers), len(self.execs)) != before:
                self.save()


# --- resolution ------------------------------------------------------------------


class Resolver:
    def __init__(self, state: State, containers: Containers):
        self.state = state
        self.containers = containers

    def resolve(self, pid: int) -> tuple[str, str]:
        """(user label value, evidence) for a host PID."""
        cid = container_of(pid)
        if cid is None:
            return self._host(pid)
        return self._container(pid, cid)

    def _host(self, pid: int) -> tuple[str, str]:
        loginuid = read_loginuid(pid)
        if loginuid != UNSET_LOGINUID:
            return username(loginuid), "loginuid"
        uid = read_uid(pid)
        if uid is None:
            return "unknown", "gone"
        if uid == 0:
            cgroup = read_cgroup(pid)
            # Root inside someone's logind session without a loginuid, e.g. Xorg of
            # the gdm greeter in user.slice/user-<gdm uid>.slice/session-c1.scope.
            match = SESSION_OWNER_RE.search(cgroup)
            if match:
                return username(int(match.group(1))), "session"
            match = SERVICE_RE.search(cgroup)
            if match:
                return f"systemd:{match.group(1)}", "systemd"
        return username(uid), "uid"

    def _container(self, pid: int, cid: str) -> tuple[str, str]:
        current = pid
        for _ in range(64):
            stat = read_stat(current)
            if stat is None:
                break
            ppid, session, starttime = stat
            record = self.state.exec_for(cid, session)
            # A session ID outliving its leader can be reused only by a newer process.
            if record and starttime >= record["starttime"]:
                return person(record["actor"]), f"{record['source']}:exec"
            if ppid <= 1 or container_of(ppid) != cid:
                break
            current = ppid

        record = self.state.container(cid)
        if record:
            return person(record["actor"]), f"{record['source']}:{record['action']}"
        return f"docker:{self.containers.name(cid)}", "docker-name"
