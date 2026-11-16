"""Developer acceptance runner, not a project runtime or scheduled business feature."""

import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    backend = Path(__file__).resolve().parents[1]
    root = backend.parent
    frontend = root / "frontend"
    report = root / "docs" / "任务07-验证输出.txt"
    node = shutil.which("node")
    if node is None:
        raise SystemExit("Node.js is required for developer verification.")
    npm = [node, str(Path(node).parent / "node_modules/npm/bin/npm-cli.js")]
    python = sys.executable
    env = os.environ.copy()
    # This subprocess tree only; never modify the user's global proxy configuration.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(key, None)
    env.update(NO_COLOR="1", CI="1", PYTHONIOENCODING="utf-8")
    commands = [
        (frontend, npm + ["test", "--", "--reporter=dot"]),
        (frontend, npm + ["run", "test:live"]),
        (frontend, npm + ["run", "build"]),
        (backend, [python, "-m", "pytest", "-q"]),
        (backend, [python, "-m", "pip", "check"]),
        (backend, [python, "-m", "compileall", "-q", "app"]),
        (backend, [python, "scripts/smoke_console.py"]),
        (backend, [python, "-c",
                   "import json; from pathlib import Path; from app.main import create_app; "
                   "expected=json.loads(Path('docs/openapi-0.6.0.json').read_text(encoding='utf-8')); "
                   "assert create_app().openapi()==expected; print('OpenAPI 0.6.0 matches')"]),
        (frontend, npm + ["audit", "--registry=https://registry.npmjs.org", "--json",
                          "--fetch-retries=0", "--fetch-timeout=20000"]),
    ]
    outputs = [f"Final verification: {datetime.datetime.now().astimezone().isoformat()}\n"]
    for cwd, cmd in commands:
        heading = "\n$ " + " ".join(cmd) + "\n"
        print(heading, flush=True)
        run = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                             errors="replace", timeout=150)
        print(run.stdout, flush=True)
        outputs.extend([heading, run.stdout, f"\nEXIT={run.returncode}\n"])
        report.write_text("".join(outputs), encoding="utf-8")
        if run.returncode:
            return run.returncode
        if "scripts/smoke_console.py" in cmd:
            (root / "docs" / "任务07-真实HTTP核对.json").write_text(run.stdout, encoding="utf-8")
    print("All final verification commands passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
