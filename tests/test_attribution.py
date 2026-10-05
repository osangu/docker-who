import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from docker_who import attribution, cli, docker_observer


class AttributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.metadata = self.root / "containers"
        self.metadata.mkdir()
        self.cid = "a" * 64
        (self.metadata / self.cid).mkdir()
        (self.metadata / self.cid / "config.v2.json").write_text(json.dumps({
            "Name": "/example", "State": {"Pid": 10},
            "Created": "2026-01-01T00:00:00.123456789Z",
        }))
        self.state = attribution.State(str(self.root / "attribution.json"))
        self.containers = attribution.Containers(str(self.metadata))
        self.resolver = attribution.Resolver(self.state, self.containers)
        self.actor = {"pid": 9, "uid": 0, "loginuid": 1001, "comm": "docker"}
        for target, value in (
            ("PROC_ROOT", str(self.proc)),
            ("username", lambda uid: f"user-{uid}"),
        ):
            patcher = patch.object(attribution, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def process(self, pid, *, ppid=1, session=None, start=100, cgroup="",
                loginuid=attribution.UNSET_LOGINUID):
        path = self.proc / str(pid)
        path.mkdir()
        fields = ["S", str(ppid), "0", str(session or pid)] + ["0"] * 15 + [str(start)]
        (path / "stat").write_text(f"{pid} (worker (child)) " + " ".join(fields))
        (path / "cgroup").write_text(cgroup)
        (path / "loginuid").write_text(str(loginuid))
        (path / "comm").write_text("worker\n")

    def docker_process(self, pid, **kwargs):
        self.process(pid, cgroup=f"0::/system.slice/docker-{self.cid}.scope\n", **kwargs)

    def test_host_login_identity_survives_root_uid(self):
        self.process(10, loginuid=1001)
        with patch.object(attribution, "read_uid", return_value=0):
            self.assertEqual(self.resolver.resolve(10), ("user-1001", "loginuid"))

    def test_root_user_session_and_systemd_service(self):
        self.process(10, cgroup="0::/user.slice/user-1002.slice/session-1.scope")
        self.process(11, cgroup="0::/system.slice/example.service")
        with patch.object(attribution, "read_uid", return_value=0):
            self.assertEqual(self.resolver.resolve(10), ("user-1002", "session"))
            self.assertEqual(self.resolver.resolve(11), ("systemd:example", "systemd"))

    def test_missing_process_is_unknown(self):
        self.assertEqual(self.resolver.resolve(999), ("unknown", "gone"))

    def test_unobserved_container_has_name_fallback(self):
        self.docker_process(10)
        self.assertEqual(self.resolver.resolve(10), ("docker:example", "docker-name"))

    def test_exec_takes_precedence_over_container_start(self):
        self.docker_process(10, session=10)
        self.state.record_container(self.cid, self.actor, "start", "ebpf")
        exec_actor = dict(self.actor, loginuid=1002)
        self.state.record_exec(self.cid, 10, 100, "b" * 64, exec_actor, "ebpf")
        self.assertEqual(self.resolver.resolve(10), ("user-1002", "ebpf:exec"))

    def test_reparented_exec_child_retains_session_identity(self):
        self.docker_process(20, ppid=1, session=10, start=150)
        self.state.record_exec(self.cid, 10, 100, "b" * 64, self.actor, "ebpf")
        self.assertEqual(self.resolver.resolve(20), ("user-1001", "ebpf:exec"))

    def test_new_session_follows_ancestor_exec(self):
        self.docker_process(10)
        self.docker_process(20, ppid=10, session=20, start=150)
        self.state.record_exec(self.cid, 10, 100, "b" * 64, self.actor, "ebpf")
        self.assertEqual(self.resolver.resolve(20), ("user-1001", "ebpf:exec"))

    def test_record_newer_than_process_is_not_used(self):
        self.docker_process(10, start=100)
        self.state.record_exec(self.cid, 10, 200, "b" * 64, self.actor, "ebpf")
        self.assertEqual(self.resolver.resolve(10), ("docker:example", "docker-name"))

    def test_saved_state_survives_restart_and_cli_does_not_overwrite_ebpf(self):
        self.state.record_container(self.cid, self.actor, "start", "ebpf")
        self.state.record_exec(self.cid, 10, 100, "b" * 64, self.actor, "ebpf")
        self.assertFalse(self.state.record_exec(
            self.cid, 10, 100, "b" * 64, dict(self.actor, loginuid=1002), "cli"))
        loaded = attribution.State(self.state.path)
        self.assertEqual(loaded.container(self.cid)["actor"], self.actor)
        self.assertEqual(loaded.exec_for(self.cid, 10)["source"], "ebpf")

    def test_prune_keeps_live_exec_session_after_leader_exit(self):
        self.docker_process(20, session=10)
        self.state.record_exec(self.cid, 10, 100, "b" * 64, self.actor, "ebpf")
        self.state.record_exec(self.cid, 30, 100, "c" * 64, self.actor, "ebpf")
        self.state.prune(self.containers)
        self.assertIsNotNone(self.state.exec_for(self.cid, 10))
        self.assertIsNone(self.state.exec_for(self.cid, 30))

    def test_metadata_resolves_names_ids_and_unique_prefixes(self):
        for value in ("example", self.cid, self.cid[:12]):
            self.assertEqual(self.containers.resolve(value), self.cid)
        second = "aaaa" + "b" * 60
        (self.metadata / second).mkdir()
        self.assertIsNone(self.containers.resolve("aaaa"))

    def test_process_stat_handles_nested_parentheses(self):
        self.process(10, ppid=3, session=8, start=777)
        self.assertEqual(attribution.read_stat(10), (3, 8, 777))

    def test_observer_records_versioned_restart_request(self):
        observer = docker_observer.DockerObserver(self.state, self.containers)
        observer.handle("9\t0\t1001\tdocker\tPOST /v1.45/containers/example/restart HTTP/1.1")
        record = self.state.container(self.cid)
        self.assertEqual(record["action"], "restart")
        self.assertEqual(record["source"], "ebpf")
        self.assertEqual(record["actor"], self.actor)

    def test_observer_ignores_non_attribution_requests(self):
        observer = docker_observer.DockerObserver(self.state, self.containers)
        observer.handle("9\t0\t1001\tdocker\tPOST /containers/create HTTP/1.1")
        observer.handle("9\t0\t1001\tdocker\tGET /containers/example/json HTTP/1.1")
        self.assertEqual(self.state.containers, {})

    def test_cli_resolve_reads_state_without_starting_observer(self):
        self.docker_process(10)
        self.state.record_container(self.cid, self.actor, "start", "ebpf")
        before = Path(self.state.path).read_bytes()
        output = io.StringIO()
        with patch.object(cli.sys, "platform", "linux"), \
             patch.object(cli, "Containers", return_value=self.containers), \
             patch.object(cli, "watch") as watcher, contextlib.redirect_stdout(output):
            cli.main(["--state-file", self.state.path, "resolve", "10"])
        watcher.assert_not_called()
        self.assertIn("user-1001", output.getvalue())
        self.assertIn("ebpf:start", output.getvalue())
        self.assertEqual(Path(self.state.path).read_bytes(), before)

    def test_cli_ps_only_lists_docker_processes(self):
        self.docker_process(10)
        self.process(11, loginuid=1002)
        output = io.StringIO()
        with patch.object(cli.sys, "platform", "linux"), \
             patch.object(cli, "PROC_ROOT", str(self.proc)), \
             patch.object(cli, "Containers", return_value=self.containers), \
             contextlib.redirect_stdout(output):
            cli.main(["--state-file", self.state.path, "ps"])
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1].split()[0], "10")

    def test_cli_rejects_invalid_pids(self):
        for value in ("0", "-1", "invalid"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli.main(["resolve", value])
                self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
