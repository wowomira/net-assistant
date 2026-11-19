"""Project-local Windows runtime. No downloads, registry edits or implicit PATH fallback."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def publish_directory(source, destination):
    """Bounded retry for transient Windows antivirus sharing violations."""
    for attempt in range(6):
        try:
            Path(source).rename(destination)
            return
        except PermissionError:
            if attempt == 5 or Path(destination).exists():
                raise
            time.sleep(0.2 * (attempt + 1))


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_hash(path, expected):
    if sha256(path) != expected:
        raise ValueError(f"Resource checksum mismatch: {Path(path).name}")


def safe_relative(name):
    normalized = name.replace("\\", "/")
    posix, windows = PurePosixPath(normalized), PureWindowsPath(name)
    if (not normalized or posix.is_absolute() or windows.drive or windows.root
            or ".." in posix.parts or ":" in normalized):
        raise ValueError("Unsafe resource path.")
    return posix


def extract_zip(archive, target):
    target = Path(target)
    if target.exists():
        raise ValueError("Archive destination already exists; refusing to replace it.")
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        for entry in entries:
            safe_relative(entry.filename)
            if stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError("Symlinks are not allowed in runtime archives.")
        # Validation is complete before any destination file is created.
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="extract-", dir=target.parent) as temporary:
            staging = Path(temporary) / "complete"
            staging.mkdir()
            for entry in entries:
                relative = safe_relative(entry.filename)
                destination = staging.joinpath(*relative.parts)
                if entry.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(entry) as source, destination.open("xb") as out:
                        shutil.copyfileobj(source, out)
            publish_directory(staging, target)


def verify_resources(directory, expected_manifest=None):
    directory = Path(directory).absolute()
    manifest = directory / "manifest.json"
    # Windows may spell a real directory using its 8.3 alias. Check the links
    # themselves so a different spelling of an ordinary directory is accepted.
    if any(part.is_symlink() or part.is_junction() for part in (manifest, *manifest.parents)):
        raise ValueError("Redirected resource bundle or manifest.")
    if expected_manifest:
        check_hash(manifest, expected_manifest)
    value = json.loads(manifest.read_text("utf-8"))
    files = value.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Empty resource manifest.")
    expected = {safe_relative(name).as_posix(): digest for name, digest in files.items()}
    if len(expected) != len(files):
        raise ValueError("Duplicate resource paths in manifest.")
    # Install consumes entire tool directories and lets pip discover wheels.
    # Verify the directory it will actually use, including unexpected entries.
    directories = [directory]
    while directories:
        for path in directories.pop().iterdir():
            if path.is_symlink() or path.is_junction():
                raise ValueError("Redirected resource entry.")
            if path.is_dir():
                directories.append(path)
                continue
            if path == manifest:
                continue
            name = path.relative_to(directory).as_posix()
            if name not in expected or not path.is_file():
                raise ValueError(f"Unlisted or invalid resource: {name}")
            check_hash(path, expected.pop(name))
    if expected:
        raise ValueError("Resource manifest lists files missing from the bundle.")
    return value


def configure_embedded_python(root=ROOT):
    directory = Path(root).resolve() / ".runtime/python"
    pth = directory / "python313._pth"
    if not pth.is_file():
        raise ValueError("Pinned embedded Python 3.13 is missing.")
    pth.write_text(
        "python313.zip\n.\nLib/site-packages\n../../scripts\n"
        "../../net-assistant/backend\nimport site\n", encoding="utf-8")


def runtime_environment(root=ROOT, source=None):
    root = Path(root).resolve()
    env = dict(os.environ if source is None else source)
    for key in list(env):
        if key.upper().startswith("INSPECT_") or key.upper() in (
                "NET_ASSISTANT_PORTABLE", "NET_ASSISTANT_GATUS", "NET_ASSISTANT_SSH", "NET_ASSISTANT_ROOT",
                "PYTHONPATH", "PYTHONHOME", "PLAYWRIGHT_BROWSERS_PATH", "NODE_PATH"):
            del env[key]
    tools = root / ".runtime/tools"
    windows = Path(env.get("SystemRoot", "C:/Windows"))
    # Do not inherit the author's Python/Node/Nmap/SSH installations.
    env["PATH"] = os.pathsep.join(map(str, [
        root / ".runtime/python", tools / "node", tools / "nmap",
        tools / "openssh", windows / "System32",
        windows / "System32/WindowsPowerShell/v1.0", windows,
    ]))
    env.update(
        PYTHONUTF8="1", PYTHONNOUSERSITE="1",
        PLAYWRIGHT_BROWSERS_PATH=str(tools / "browsers"),
        NET_ASSISTANT_PORTABLE="1",
        NET_ASSISTANT_GATUS=str(tools / "gatus/gatus.exe"),
        NET_ASSISTANT_SSH=str(tools / "openssh/ssh.exe"),
        NET_ASSISTANT_ROOT=str(root),
    )
    return env


def run(command, root=ROOT, cwd=None):
    subprocess.run([str(part) for part in command], check=True,
                   cwd=cwd or root, env=runtime_environment(root))


def _install_archive(resources, archive, destination, subdirectory=None):
    if destination.exists():
        with zipfile.ZipFile(resources / archive) as source:
            prefix = (subdirectory + "/") if subdirectory else ""
            for entry in source.infolist():
                if entry.is_dir() or not entry.filename.startswith(prefix):
                    continue
                name = entry.filename[len(prefix):]
                if not name or name == "python313._pth":
                    continue
                target = destination / name
                if not target.is_file() or sha256(target) != hashlib.sha256(source.read(entry)).hexdigest():
                    raise ValueError(f"Installed archive differs: {archive}/{name}; use a clean runtime.")
        return
    if subdirectory:
        with tempfile.TemporaryDirectory(prefix="tool-", dir=destination.parent) as temporary:
            staging = Path(temporary) / "unpacked"
            extract_zip(resources / archive, staging)
            publish_directory(staging / subdirectory, destination)
    else:
        extract_zip(resources / archive, destination)


def copy_resource_file(source, destination):
    """Idempotent even when upstream licenses are read-only; refuse local tampering."""
    source, destination = Path(source), Path(destination)
    if destination.exists():
        if sha256(source) != sha256(destination):
            raise ValueError(f"Installed resource differs: {destination.name}; use a clean runtime.")
        return str(destination)
    return shutil.copyfile(source, destination)


def install(root=ROOT):
    """Offline rebuild, including frontend dependencies; publish ready marker last."""
    root = Path(root).resolve()
    runtime = root / ".runtime"
    resources = runtime / "resources"
    for name in (".runtime", ".runtime/resources", ".runtime/tools", ".runtime/python",
                 ".runtime/frontend", ".runtime/npm-cache", ".runtime/configs",
                 ".runtime/tools/node", ".runtime/tools/openssh", ".runtime/tools/gatus",
                 ".runtime/tools/browsers", ".runtime/tools/swagger"):
        target = root / name
        if target.resolve() != target:
            raise ValueError("Redirected runtime path is not supported.")
    lock = json.loads((root / "runtime.lock.json").read_text("utf-8"))
    verify_resources(resources, lock["resource_manifest_sha256"])
    tools = runtime / "tools"
    tools.mkdir(parents=True, exist_ok=True)
    marker = runtime / "portable-ready.json"
    marker.unlink(missing_ok=True)  # A failed repair never advertises readiness.
    _install_archive(resources, "python.zip", runtime / "python")
    configure_embedded_python(root)
    _install_archive(resources, "node.zip", tools / "node", "node-v24.11.0-win-x64")
    _install_archive(resources, "openssh.zip", tools / "openssh", "OpenSSH-Win64")
    for name in ("browsers", "gatus", "swagger"):
        shutil.copytree(resources / name, tools / name, dirs_exist_ok=True,
                        copy_function=copy_resource_file)
    python = runtime / "python/python.exe"
    # Embedded Python intentionally has no system pip/venv binding.
    pip_wheel = next((resources / "wheels").glob("pip-25.2-*.whl"))
    packages = runtime / "python/Lib/site-packages"
    packages.mkdir(parents=True, exist_ok=True)
    code = "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
    run([python, "-c", code, pip_wheel, "install", "--no-index", "--only-binary=:all:",
         "--find-links", resources / "wheels", "--target", packages, "--upgrade",
         "-r", root / "net-assistant/backend/requirements-collaboration.txt", "pip==25.2"], root)
    run([python, "-m", "pip", "check"], root)
    import workspace
    workspace.sync_frontend(root)
    frontend = runtime / "frontend"
    npm = tools / "node/npm.cmd"
    cache = runtime / "npm-cache"
    shutil.copytree(resources / "npm-cache", cache, dirs_exist_ok=True)
    run([npm, "ci", "--offline", "--cache", cache,
         "--ignore-scripts", "--no-audit", "--no-fund"], root, frontend)
    run([npm, "run", "build"], root, frontend)
    workspace.write_configs(root)
    verify_installed(root)
    marker.write_text(json.dumps({"resource_manifest_sha256": lock["resource_manifest_sha256"],
                                 "platform": "windows-x64", "app": "0.10.0"}, indent=2),
                      encoding="utf-8")
    print("Project-local runtime prepared OFFLINE. No database, account or service was changed.")


def verify_installed(root=ROOT):
    root = Path(root).resolve()
    required = [
        ".runtime/python/python.exe", ".runtime/tools/node/node.exe",
        ".runtime/tools/openssh/ssh.exe", ".runtime/tools/gatus/gatus.exe",
        ".runtime/tools/swagger/swagger-ui-bundle.js", ".runtime/tools/swagger/swagger-ui.css",
        ".runtime/frontend/dist/index.html",
    ]
    for name in required:
        if not (root / name).is_file():
            raise ValueError(f"Required runtime component missing: {name}")
    if not list((root / ".runtime/tools/browsers").glob(
            "chromium_headless_shell-*/chrome-headless-shell-win64/chrome-headless-shell.exe")):
        raise ValueError("Pinned Chromium browser missing.")
    if (root / ".runtime/python/pyvenv.cfg").exists():
        raise ValueError("Portable runtime must not depend on a bound venv.")
    lock = root / "runtime.lock.json"
    if lock.is_file():
        for name, expected in json.loads(lock.read_text("utf-8")).get("installed_files", {}).items():
            relative = safe_relative(name)
            path = root.joinpath(*relative.parts)
            if not path.resolve().is_relative_to(root):
                raise ValueError("Installed runtime redirected outside checkout.")
            check_hash(path, expected)


if __name__ == "__main__":
    try:
        install()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Portable setup failed: {error}", file=sys.stderr)
        sys.exit(1)
