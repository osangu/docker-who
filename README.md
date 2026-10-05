# Docker Who

**Who is behind this Docker process?**

Docker Who attributes Linux processes to the local users who started a container
or opened a `docker exec` session. It observes Docker requests with eBPF and
matches them to host PIDs, so processes running as `root` inside a container can
still be associated with the requesting user.

This is an early, standalone extraction of the attribution engine. The Python
runtime uses only the standard library; the observer requires the external
`bpftrace` executable.

## What it does

- Records the local caller of container start, restart, and exec requests.
- Matches exec sessions and their descendants to the requesting user.
- Saves attribution across observer restarts.
- Lists Docker processes or resolves arbitrary host PIDs, with an evidence column.
- Reads Docker metadata from files without mounting or calling `docker.sock`.

## Requirements

- A native Linux host with rootful Docker Engine and Python 3.10 or later.
- `bpftrace` with `fentry`/`fexit` support. The original observer used version 0.23.
- Kernel BTF at `/sys/kernel/btf/vmlinux`, the functions used by the tracing
  script, and audit login UID support (`CONFIG_AUDIT`).
- Permission to read host `/proc`, Docker container metadata, and containerd task
  files. Run the examples as root on the host.

Docker Desktop on macOS or Windows, rootless Docker, remote Docker daemons,
and Kubernetes are outside the current scope. A kernel version alone does not
guarantee the probes can attach; check the observer logs on your host.

## Install from source

From this checkout on the Linux Docker host:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/docker-who --help
```

Install `bpftrace` separately using your distribution's package manager. The
included Dockerfile is an optional packaging scaffold; it does not configure
host permissions or mounts.

## Usage

Start the observer before starting containers or exec sessions:

```sh
sudo .venv/bin/docker-who watch
```

Leave it running. In another terminal, list container processes:

```sh
sudo .venv/bin/docker-who ps
```

Resolve specific host PIDs, including processes outside Docker:

```sh
# Replace PID with an actual host PID. Multiple PIDs are accepted.
sudo .venv/bin/docker-who resolve PID
```

Both commands display `PID`, `USER`, `EVIDENCE`, `CONTAINER`, and `COMMAND`.
They read saved attribution without starting the observer or changing state.
`watch` writes state and may supplement observations by scanning live Docker CLI
processes. Stop it with Ctrl+C.

The default state file is `/var/lib/docker-who/attribution.json`. To change it,
use the same option for the watcher and readers:

```sh
sudo .venv/bin/docker-who --state-file /path/to/attribution.json watch
sudo .venv/bin/docker-who --state-file /path/to/attribution.json ps
```

The option goes **before** the subcommand. Keep the state file writable by the
observer and readable only by users who should see attribution records.

## How attribution works

For a **Docker process**, the resolver checks:

1. A recorded exec session for the process or one of its ancestors.
2. A recorded container start or restart request.
3. The fallback `docker:<container-name>` when no user record exists.

For a **host process**, it uses the audit login UID first, then a root process's
systemd user session or service, then the process UID. A service is labeled
`systemd:<unit>` rather than guessing a human owner. Unknown account IDs become
`uid-<uid>`.

Exec matching uses process session IDs and start times. An exec's children can
retain attribution after their original parent exits. Active Docker CLI scans
are a heuristic fallback, indicated by `cli:*`; directly observed requests use
`ebpf:*` evidence. These records describe observed callers, not verified ownership
or successful completion of a Docker API request.

## Configuration

Set these environment variables before starting the command. When using `sudo`,
pass explicit values through `sudo env NAME=value ...` if your sudo policy clears
the environment.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROC_ROOT` | `/proc` | Host process information |
| `DOCKER_CONTAINERS_DIR` | `/var/lib/docker/containers` | Docker `config.v2.json` files |
| `CONTAINERD_TASK_DIR` | `/run/containerd/io.containerd.runtime.v2.task/moby` | Exec PID files |
| `STATE_FILE` | `/var/lib/docker-who/attribution.json` | Persistent attribution; overridden by `--state-file` |
| `DOCKER_SOCKETS` | `/var/run/docker.sock,/run/docker.sock` | Comma-separated local socket paths to observe |
| `BPFTRACE` | `bpftrace` | Observer executable |

Docker and containerd paths are implementation details and can vary by
installation. Match them to the actual host layout.

## Limitations

- Historical callers cannot be recovered once their request and CLI process
  are gone. Containers without a record keep the container-name fallback.
- Automation is attributed to the service account making the Docker request.
- Automatic restarts can retain a previous record; they do not reveal a new caller.
- UID names come from the host account database. They are not an identity directory.
- The tracing script currently observes `ksys_write`, local socket file
  descriptors below 64, and request prefixes. Other write paths, split requests,
  inherited connections, or already-open sockets can be missed.
- This is a diagnostic tool, not an authorization or tamper-resistant audit system.

For tracing prerequisites, see the [bpftrace fentry/fexit documentation](https://bpftrace.org/docs/release_023/language#fentry-and-fexit).

## Development

```sh
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Tests use temporary process and Docker metadata fixtures. They do not require
a Docker daemon or kernel tracing. Live eBPF behavior must be validated separately
on a Linux Docker host.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

## License

[MIT](LICENSE). Copyright (c) 2026 osangu.
