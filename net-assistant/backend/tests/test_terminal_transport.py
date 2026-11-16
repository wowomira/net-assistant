"""Real subprocess/pipe and loopback refusal tests; not an SSH server or device emulation."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from app.terminal.config import Target, TerminalPlan
from app.terminal.transport import OpenSSHTransport, TransportFailure


def target(tmp_path, **changes):
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("not-a-real-private-key")
    hosts.write_text("not-a-real-host-key")
    return Target.model_validate({
        "id": "isolated", "label": "isolated", "address": "127.0.0.1", "port": 22,
        "username": "test", "private_key": key, "known_hosts": hosts,
        "vendor": "cisco", "platform": "ios", "version": "test",
        "command_timeout_seconds": 1, **changes})


@pytest.mark.parametrize("changes", [
    {"address": "example.invalid"}, {"address": "0.0.0.0"}, {"address": "239.1.2.3"},
    {"address": "192.0.2.0/24"}, {"username": "-oProxyCommand=bad"},
    {"private_key": "relative"}, {"known_hosts": "relative"},
    {"vendor": "huawei", "platform": "ios"},
])
def test_server_enrollment_rejects_unbounded_or_invalid_destinations(tmp_path, changes):
    with pytest.raises(ValueError):
        target(tmp_path, **changes)


def test_enrollment_rejects_duplicate_ids(tmp_path):
    item = target(tmp_path)
    with pytest.raises(ValueError):
        TerminalPlan(targets=[item, item])


def harness(tmp_path, monkeypatch, body):
    script = tmp_path / "pipe_harness.py"
    script.write_text(body, encoding="utf-8")
    original = subprocess.Popen
    arguments = []
    def start(args, **kwargs):
        arguments.extend(args)
        return original([sys.executable, "-u", str(script)], **kwargs)
    monkeypatch.setattr(subprocess, "Popen", start)
    return arguments


def test_real_process_prompt_input_output_and_strict_openssh_options(tmp_path, monkeypatch):
    args = harness(tmp_path, monkeypatch, """
import sys
sys.stdout.write('lab#'); sys.stdout.flush()
for command in sys.stdin:
    print(command.strip(), flush=True)
    print('actual-pipe-response', flush=True)
    sys.stdout.write('lab#'); sys.stdout.flush()
""")
    connection = OpenSSHTransport(target(tmp_path))
    try:
        connection.connect()
        output = connection.run("show version")
        assert "actual-pipe-response" in output
        assert "show version" in output
        assert "StrictHostKeyChecking=yes" in args
        assert "IdentityAgent=none" in args
        assert "PasswordAuthentication=no" in args
        assert "ClearAllForwardings=yes" in args
        assert "none" == args[args.index("-F") + 1]
        pid = connection.process.pid
    finally:
        connection.close()
    assert connection.process.poll() is not None
    assert not connection.reader.is_alive()


@pytest.mark.parametrize("reply,code", [
    ("--More--", "device_interaction_required"),
    ("Confirm [Y/N]", "device_interaction_required"),
    ("x" * 70000, "output_limit_exceeded"),
])
def test_unhandled_prompts_and_excessive_output_fail_closed(tmp_path, monkeypatch, reply, code):
    harness(tmp_path, monkeypatch, f"""
import sys, time
sys.stdout.write('lab#'); sys.stdout.flush()
for command in sys.stdin:
    print({reply!r}, flush=True)
    time.sleep(3)
""")
    connection = OpenSSHTransport(target(tmp_path))
    try:
        connection.connect()
        with pytest.raises(TransportFailure) as error:
            connection.run("show version")
        assert error.value.code == code
        assert error.value.sent is True
    finally:
        connection.close()


def test_timeout_and_unprivileged_account_are_not_success(tmp_path, monkeypatch):
    harness(tmp_path, monkeypatch, """
import sys,time
sys.stdout.write('lab#'); sys.stdout.flush()
for command in sys.stdin:
    time.sleep(5)
""")
    connection = OpenSSHTransport(target(tmp_path))
    try:
        connection.connect()
        with pytest.raises(TransportFailure, match="ssh_timeout"):
            connection.run("show version")
    finally:
        connection.close()


def test_actual_system_openssh_refused_loopback_does_not_become_ready(tmp_path):
    # Bound but not listening: OS refuses connections; no scan and no external traffic.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        connection = OpenSSHTransport(target(tmp_path, port=sock.getsockname()[1]))
        with pytest.raises(TransportFailure):
            connection.connect()
        assert connection.process is not None
        assert connection.process.poll() is not None
