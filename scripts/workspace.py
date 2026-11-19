"""Safe collaboration launcher; working DB is read only with explicit seed-build --source."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PRIMARY_KEYS = {
    "auth_users": "id", "auth_sessions": "token_hash", "auth_throttles": "key",
    "access_audit": "sequence", "terminal_sessions": "id", "terminal_operations": "id",
}


def layout(root=ROOT):
    root = Path(root).resolve()
    runtime = root / ".runtime"
    portable = runtime / "python/python.exe"
    return {
        "root": root, "runtime": runtime, "backend": root / "net-assistant/backend",
        "python": portable if portable.is_file() else runtime / (
            "venv/Scripts/python.exe" if os.name == "nt" else "venv/bin/python"),
        "database": runtime / "data/development.sqlite", "configs": runtime / "configs",
        "seed": runtime / "seeds/inspection-seed.sqlite",
        "frontend": runtime / "frontend", "frontend_dist": runtime / "frontend/dist",
    }


def write_configs(root=ROOT):
    paths = layout(root)
    directory = paths["configs"]
    directory.mkdir(parents=True, exist_ok=True)
    values = {
        "scope.local.json": {
            "name": "collaboration-loopback-only", "engine": "nmap", "nmap_path": "nmap",
            "targets": ["127.0.0.1"], "ports": [8001], "http_ports": [8001],
            "allow_loopback": True, "icmp_enabled": False, "arp_enabled": False,
            "hostname_enabled": False, "nmap_os_detection": False, "mdns_enabled": False,
            "screenshots_enabled": False, "nmap_host_timeout_seconds": 30,
            "timeout_ms": 2000, "budget_seconds": 60,
        },
        "daily-scan.local.json": {
            "name": "collaboration-disabled", "enabled": False, "at": "09:00",
            "utc_offset_minutes": 480, "scan_config": "scope.local.json",
            "database": "../data/development.sqlite", "report_directory": "../reports",
        },
        "switches.local.json": {
            "enabled": False, "database": "../data/development.sqlite",
            "scan_config": "scope.local.json", "storage": "../data/switch-runtime",
            "targets": [], "profiles": [],
        },
        "monitoring.local.json": {
            "api_url": "http://127.0.0.1:18081", "allowed_hosts": [],
            "allow_public": False, "allow_loopback": False, "endpoints": [],
        },
        "terminal.local.json": {"targets": []},
        "collection.local.json": {
            "enabled": False, "device_id": str(__import__("uuid").uuid4()),
            "label": "My Windows host", "interval_seconds": 300,
        },
    }
    for name, value in values.items():
        try:
            with (directory / name).open("x", encoding="utf-8") as output:
                json.dump(value, output, ensure_ascii=False, indent=2)
                output.write("\n")
        except FileExistsError:
            pass  # Never overwrite a collaborator's configuration.


def server_environment(root=ROOT, source=None):
    # Legacy workers read INSPECT_*; do not accidentally borrow their database/plans.
    environment = dict(os.environ if source is None else source)
    for key in list(environment):
        if key.upper().startswith("INSPECT_"):
            del environment[key]
    environment["PYTHONUTF8"] = "1"
    if (Path(root) / ".runtime/portable-ready.json").is_file():
        from runtime_support import runtime_environment
        return runtime_environment(root, environment)
    return environment


def check_database(path):
    """Read-only deployment preflight; version alone is insufficient for early 0006."""
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError("Database absent; run: python scripts/workspace.py init")
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("Database integrity check failed.")
            if db.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("Database foreign-key check failed.")
            if db.execute("SELECT version_num FROM alembic_version").fetchall() != [
                ("0006_access_terminal",)
            ]:
                raise ValueError("Database schema revision mismatch; no automatic migration.")
            for table, column in PRIMARY_KEYS.items():
                info = {row[1]: row for row in db.execute(f'PRAGMA table_info("{table}")')}
                row = info.get(column)
                if row is None or not row[3] or not row[5]:
                    raise ValueError(f"Database schema mismatch: {table}.{column}; no writes performed.")
    except sqlite3.Error as error:
        raise ValueError("Database schema unavailable; no automatic migration.") from error


def sync_frontend(root=ROOT):
    paths = layout(root)
    source = paths["root"] / "net-assistant/frontend"
    target = paths["frontend"]
    files = ("package.json", "package-lock.json", "index.html", "tsconfig.json",
             "vite.config.ts", "vite.live.config.ts")
    directories = ("src", "tests-live")
    # Check every destination before creating directories or copying any files.
    for name in (*files, *directories):
        destination = target / name
        if (destination.resolve() != destination
                or (destination.is_file() and destination.stat().st_nlink > 1)):
            raise ValueError("Refusing to sync a redirected frontend runtime path.")
    target.mkdir(parents=True, exist_ok=True)
    # Explicit allowlist: no .env, local configuration, old dist, or node_modules.
    for name in files:
        if (source / name).is_file():
            shutil.copy2(source / name, target / name)
    for name in directories:
        destination = target / name
        if destination.is_dir():
            shutil.rmtree(destination)
        if (source / name).is_dir():
            shutil.copytree(source / name, destination,
                            ignore=shutil.ignore_patterns("__pycache__", "*.local.*", ".env*"))


def run(arguments, *, cwd=ROOT, env=None):
    subprocess.run([str(item) for item in arguments], cwd=cwd, env=env, check=True)


def isolated_python_command(python, code):
    """One owned OS process, not Windows venv's redirector plus an orphan child."""
    metadata = json.loads(subprocess.check_output(
        [str(python), "-c", "import sys,sysconfig,json;print(json.dumps("
         "{'base':sys._base_executable,'packages':sysconfig.get_paths()['purelib']}))"],
        text=True, encoding="utf-8", timeout=30))
    prefix = ("import sys,site;"
              "sys.stdout.reconfigure(encoding='utf-8');sys.stderr.reconfigure(encoding='utf-8');"
              f"site.addsitedir({metadata['packages']!r});")
    return [metadata["base"], "-I", "-S", "-c", prefix + code]


def npm_path():
    portable = ROOT / ".runtime/tools/node/npm.cmd"
    if (ROOT / ".runtime/portable-ready.json").is_file():
        if not portable.is_file():
            raise ValueError("Project-local npm missing; repair with bootstrap.ps1.")
        return str(portable)
    executable = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not executable:
        raise ValueError("npm missing. Install Node.js 24.x and reopen the terminal.")
    return executable


def require_runtime():
    python = layout()["python"]
    if not python.is_file():
        raise ValueError("Runtime absent; run: python scripts/workspace.py setup")
    if python == ROOT / ".runtime/python/python.exe" and not (
            ROOT / ".runtime/portable-ready.json").is_file():
        raise ValueError("Portable setup is incomplete; run bootstrap.ps1 setup before using it.")
    return python


def setup(index_url=None, wheelhouse=None):
    import venv  # Legacy developer setup only; embedded portable Python has no venv.
    if sys.version_info[:2] != (3, 13):
        raise ValueError("Verified Python version is 3.13.x (64-bit). Use Python 3.13.")
    if sys.maxsize <= 2**32:
        raise ValueError("A 64-bit Python interpreter is required.")
    npm = npm_path()
    node = shutil.which("node")
    version = subprocess.check_output([node, "--version"], text=True).strip() if node else ""
    if version != "v24.11.0":
        raise ValueError("Pinned Node.js is 24.11.0 (npm 11.6.1). Use this version or bootstrap.ps1.")
    paths = layout()
    if not paths["python"].is_file():
        venv.EnvBuilder(with_pip=True).create(paths["runtime"] / "venv")
    pip = [paths["python"], "-m", "pip", "install"]
    if wheelhouse:
        pip += ["--no-index", "--find-links", str(Path(wheelhouse).resolve())]
    elif index_url:
        pip += ["--index-url", index_url]
    run([*pip, "-r", paths["backend"] / "requirements-collaboration.txt"])
    run([paths["python"], "-m", "pip", "check"])
    sync_frontend()
    run([npm, "ci"], cwd=paths["frontend"])
    run([npm, "run", "build"], cwd=paths["frontend"])
    write_configs()
    print("Setup complete. No database was migrated and no service was installed.")
    print("Next: python scripts/workspace.py init")


def backend_imports():
    sys.path.insert(0, str(layout()["backend"]))


def init_database():
    paths = layout()
    write_configs(paths["root"])
    if paths["database"].exists():
        check_database(paths["database"])
        print("Existing development database matches; left unchanged.")
        return
    if paths["seed"].is_file():
        from data_seed import import_seed
        import_seed(paths["seed"], paths["database"])
        print(f"Initialized development database from private historical seed: {paths['database']}")
        print("No accounts imported. Run create-user; no collection or scan was started.")
        return
    backend_imports()
    from app import main as _models  # Register mapped tables, including assets.
    from app.discovery.store import initialize_database
    database = initialize_database(paths["database"])
    database.engine.dispose()
    check_database(paths["database"])
    print(f"Created empty development database: {paths['database']}")
    print("Next: python scripts/workspace.py create-user YOUR_USERNAME --role admin")


def build_app():
    paths = layout()
    check_database(paths["database"])
    if not (paths["frontend_dist"] / "index.html").is_file():
        raise ValueError("Console build missing; run: python scripts/workspace.py setup")
    backend_imports()
    from app.main import create_app
    app = create_app(
        database_path=paths["database"], frontend_dist=paths["frontend_dist"],
        schedule_config_path=paths["configs"] / "daily-scan.local.json",
        monitoring_config_path=paths["configs"] / "monitoring.local.json",
        switch_config_path=paths["configs"] / "switches.local.json",
        terminal_config_path=paths["configs"] / "terminal.local.json",
        allow_anonymous_reads=False, allow_insecure_local_http=True,
    )
    swagger = paths["runtime"] / "tools/swagger"
    if swagger.is_dir():
        from app.runtime_tools import install_local_docs
        install_local_docs(app, swagger)
    elif os.environ.get("NET_ASSISTANT_PORTABLE") == "1":
        raise ValueError("Local Swagger resources missing; repair with bootstrap.ps1.")
    return app


def doctor():
    paths = layout()
    print("Supported baseline: Windows x64 / Python 3.13.x / Node.js 24.x")
    if (paths["runtime"] / "portable-ready.json").is_file():
        from runtime_support import verify_installed, runtime_environment
        verify_installed()
        env = runtime_environment()
        for name in ("node", "nmap", "ssh"):
            print(f"{name}: {shutil.which(name, path=env['PATH']) or 'MISSING; supply component first'}")
        print("Portable Python/Node/Gatus/SSH/Chromium/Swagger checked. Npcap and device permissions are separate.")
        return
    for name in ("python", "database", "frontend_dist"):
        path = paths[name]
        print(f"{name}: {'present' if path.exists() else 'MISSING'} | {path}")
    for name in ("node", "nmap", "ssh"):
        print(f"{name}: {shutil.which(name) or 'not installed / not on PATH'}")
    gatus = paths["backend"] / "tools/gatus/bin/gatus.exe"
    print(f"gatus (optional): {gatus if gatus.is_file() else 'not installed'}")
    if os.name == "nt":
        powershell = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        print(f"Windows PowerShell: {powershell if powershell.is_file() else 'MISSING'}")
        edge = [Path(os.environ.get(key, "")) / "Microsoft/Edge/Application/msedge.exe"
                for key in ("PROGRAMFILES(X86)", "PROGRAMFILES")]
        print(f"Edge (optional screenshot): {next((str(p) for p in edge if p.is_file()), 'not installed')}")
    print("No secrets, credentials or environment-variable values were printed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("setup", help="create isolated venv and frontend build")
    sources = install.add_mutually_exclusive_group()
    sources.add_argument("--index-url")
    sources.add_argument("--wheelhouse", help="existing wheels directory; npm still needs its packages")
    sub.add_parser("doctor", help="read-only dependency locations")
    sub.add_parser("init", help="initialize only the isolated development database")
    seed_build = sub.add_parser("seed-build", help="read-only snapshot and sanitized private history bundle")
    seed_build.add_argument("--source", required=True, help="explicit working database to read, never migrate")
    seed_build.add_argument("--output", type=Path, default=layout()["seed"],
                            help="database inside a NEW bundle directory; existing directories are refused")
    seed_import = sub.add_parser("seed-import", help="import history; never overwrite/merge nonempty databases")
    seed_import.add_argument("--seed", type=Path, default=layout()["seed"])
    seed_import.add_argument("--into-empty", action="store_true",
                             help="explicitly allow an existing completely empty compatible runtime")
    seed_check = sub.add_parser("seed-check", help="read-only seed checksums, rows, schema and artifacts")
    seed_check.add_argument("--seed", type=Path, default=layout()["seed"])
    user = sub.add_parser("create-user", help="prompt securely; never pass passwords as arguments")
    user.add_argument("username")
    user.add_argument("--role", choices=("admin", "operator", "viewer"), default="viewer")
    serve = sub.add_parser("serve", help="explicit loopback-only HTTP development server")
    serve.add_argument("--port", type=int, default=8001)
    start = sub.add_parser("start", help="owned foreground API + explicitly enabled workers")
    start.add_argument("--port", type=int, default=8001)
    tool_import = sub.add_parser("import-nmap", help="copy your licensed complete Nmap directory locally")
    tool_import.add_argument("--source", required=True, type=Path)
    test = sub.add_parser("test")
    test.add_argument("--local-tools", action="store_true", help="opt in to real loopback tools")
    sub.add_parser("check", help="verify dependencies, database and production console build")
    args = parser.parse_args()
    if args.command == "setup":
        setup(args.index_url, args.wheelhouse)
        return
    if args.command == "doctor":
        doctor()
        return
    python = require_runtime()
    environment = server_environment()
    if Path(sys.executable).resolve() != python.resolve():
        run([python, Path(__file__).resolve(), *sys.argv[1:]], env=environment)
        return
    # bootstrap.ps1 invokes the embedded interpreter directly, so there may be
    # no re-exec above. Workers in THIS process need the same local-tool policy.
    os.environ.clear()
    os.environ.update(environment)
    if args.command == "import-nmap":
        from runtime_manager import import_nmap
        import_nmap(args.source)
    elif args.command == "start":
        from runtime_manager import start
        start(args.port)
    elif args.command == "init":
        init_database()
    elif args.command == "seed-build":
        from data_seed import build_seed
        manifest = build_seed(args.source, args.output)
        print(f"Private historical seed created: {args.output.resolve()}")
        print("Rows: " + json.dumps({name: data["rows"] for name, data in manifest["tables"].items()}))
        print("Access/terminal tables excluded; sanitization recorded; no source writes, service changes or uploads.")
    elif args.command == "seed-import":
        from data_seed import import_seed
        receipt = import_seed(args.seed, layout()["database"], into_empty=args.into_empty)
        print(f"Historical data imported into: {layout()['database']}")
        print("Rows: " + json.dumps(receipt["table_counts"]))
        print("No accounts imported; existing collection configuration was not changed.")
        if "receipt_warning" in receipt:
            print(receipt["receipt_warning"])
    elif args.command == "seed-check":
        from data_seed import validate_seed
        manifest = validate_seed(args.seed)
        print("Seed schema, checksums, row fingerprints, excluded tables and artifacts checked.")
        print("Snapshot window (UTC): " + json.dumps(manifest["source_snapshot"]))
    elif args.command == "create-user":
        check_database(layout()["database"])
        run([python, "-m", "app.auth.cli", "--database", layout()["database"],
             "create-user", args.username, "--role", args.role],
            cwd=layout()["backend"], env=environment)
    elif args.command == "serve":
        if not 1 <= args.port <= 65535:
            raise ValueError("Port must be in 1..65535.")
        app = build_app()
        with closing(sqlite3.connect(layout()["database"])) as db:
            if not db.execute("SELECT count(*) FROM auth_users WHERE enabled=1").fetchone()[0]:
                raise ValueError("No enabled accounts. Run create-user first; no default password exists.")
        print(f"Local development only: http://127.0.0.1:{args.port}/docs", flush=True)
        print("Login via POST /api/v1/auth/login in /docs, then open /console/ in the same browser.", flush=True)
        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, workers=1, proxy_headers=False)
    elif args.command == "test":
        run([python, "-m", "unittest", "discover", "-s", "tests", "-v"], env=environment)
        if args.local_tools:
            environment["RUN_LOCAL_TOOLS"] = "1"
        else:
            environment.pop("RUN_LOCAL_TOOLS", None)
        run([python, "-m", "pytest", "-q"], cwd=layout()["backend"], env=environment)
        sync_frontend()
        run([npm_path(), "test"], cwd=layout()["frontend"], env=environment)
        run([npm_path(), "run", "build"], cwd=layout()["frontend"], env=environment)
    elif args.command == "check":
        run([python, "-m", "pip", "check"], env=environment)
        build_app()
        print("Database schema and console build checked; no probes or migrations performed.")


if __name__ == "__main__":
    try:
        main()
    except sqlite3.Error:
        print("ERROR: SQLite operation failed; source database was not modified.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
