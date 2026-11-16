"""System OpenSSH PTY transport; strict enrolled host keys, key auth, bounded output.

No subprocess shell, agent, client-provided hostname, forwarding, password prompts or
automatic host-key acceptance. A CLI prompt means command completion, not business success.
"""
import os
import queue
import re
import shutil
import subprocess
import threading
import time

PROMPT = re.compile(r"(?:^|[\r\n])(?:[A-Za-z0-9_.:/()~-]{1,100}[>#]|"
                    r"<[A-Za-z0-9_.:/()~-]{1,100}>|\[[A-Za-z0-9_.:/()~-]{1,100}\])[ \t]*\Z")
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
MAX_OUTPUT = 65536


class TransportFailure(Exception):
    def __init__(self, code, *, sent=False):
        self.code, self.sent = code, sent
        super().__init__(code)


def clean_output(text):
    text = ANSI.sub("", text)
    return "".join(ch for ch in text if ch in "\r\n\t" or ord(ch) >= 32 and ord(ch) != 127)


class OpenSSHTransport:
    def __init__(self, target):
        self.target = target
        self.process = None
        self.chunks = queue.Queue(maxsize=32)
        self.stopped = threading.Event()
        self.reader = None

    def connect(self):
        executable = shutil.which("ssh")
        if not executable:
            raise TransportFailure("ssh_client_unavailable")
        target = self.target
        args = [executable, "-F", "none", "-tt",
                "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=yes",
                "-o", "GlobalKnownHostsFile=none",
                "-o", f"UserKnownHostsFile={target.known_hosts}",
                "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
                "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
                "-o", "ForwardX11=no", "-o", "PermitLocalCommand=no",
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR",
                "-i", str(target.private_key), "-p", str(target.port),
                "-l", target.username, target.address]
        try:
            self.process = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.reader = threading.Thread(target=self._read, daemon=True, name="terminal-ssh-output")
            self.reader.start()
            banner = self._until_prompt(15)
            # Fail closed for unprivileged Cisco-style prompts. We do not auto-send enable passwords.
            if target.vendor in ("cisco", "ruijie") and banner.rstrip().endswith(">"):
                raise TransportFailure("privileged_device_account_required")
        except (OSError, TransportFailure) as error:
            self.close()
            if isinstance(error, TransportFailure):
                raise
            raise TransportFailure("ssh_connect_failed") from error

    def _read(self):
        try:
            while not self.stopped.is_set():
                chunk = os.read(self.process.stdout.fileno(), 4096)
                while not self.stopped.is_set():
                    try:
                        self.chunks.put(chunk, timeout=0.2)
                        break
                    except queue.Full:
                        continue
                if not chunk:
                    break
        except (OSError, ValueError):
            pass
        finally:
            # An EOF is not interpreted as successful command completion.
            if not self.stopped.is_set():
                try:
                    self.chunks.put(b"", timeout=0.2)
                except queue.Full:
                    pass

    def _until_prompt(self, seconds, *, sent=False):
        deadline = time.monotonic() + seconds
        chunks = bytearray()
        while time.monotonic() < deadline:
            try:
                data = self.chunks.get(timeout=min(0.2, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                if self.process.poll() is not None:
                    raise TransportFailure("ssh_disconnected", sent=sent)
                continue
            if not data:
                raise TransportFailure("ssh_disconnected", sent=sent)
            chunks.extend(data)
            if len(chunks) > MAX_OUTPUT:
                raise TransportFailure("output_limit_exceeded", sent=sent)
            text = clean_output(chunks.decode("utf-8", errors="replace"))
            if re.search(r"(?:--More--|---- More ----|Press any key|\[Y/N\]|\[yes/no\])", text, re.I):
                # Never automatically answer a device-level confirmation or paging prompt.
                raise TransportFailure("device_interaction_required", sent=sent)
            if PROMPT.search(text):
                return text
        raise TransportFailure("ssh_timeout", sent=sent)

    def run(self, command):
        if not self.process or self.process.poll() is not None:
            raise TransportFailure("ssh_disconnected")
        if not command or any(ord(ch) < 32 or ord(ch) == 127 for ch in command):
            raise TransportFailure("invalid_command")
        try:
            # A partial write failure is still an unknown outcome, not safe to retry.
            self.process.stdin.write((command + "\n").encode())
            self.process.stdin.flush()
        except (OSError, ValueError) as error:
            raise TransportFailure("ssh_disconnected", sent=True) from error
        return self._until_prompt(self.target.command_timeout_seconds, sent=True)

    def close(self):
        self.stopped.set()
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            for stream in (self.process.stdin, self.process.stdout):
                if stream:
                    stream.close()
        if self.reader and self.reader is not threading.current_thread():
            self.reader.join(timeout=2)
