"""Build a fresh, hash-inventoried source snapshot without touching the source Git index."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def source_path(root, name):
    relative = PurePosixPath(name)
    if (not relative.parts or relative.as_posix() != name or relative.is_absolute()
            or ".." in relative.parts or "\\" in name or ":" in name):
        raise ValueError(f"Invalid source path: {name}")
    path = root / relative
    if path.resolve() != path:
        raise ValueError(f"Redirected source path: {name}")
    return path


def digest(path):
    # Git applies .gitattributes/core.autocrlf during checkout. Treat only this
    # expected text line-ending conversion as equivalent; preserve every other byte.
    data = Path(path).read_bytes()
    if b"\0" not in data:
        data = data.replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def sanitize_document(text):
    # Historical reports are useful, but are not a reason to publish real lab identity.
    text = re.sub(r"[A-Za-z]:[\\/](?:wenjian|work enhance)[^`\"\r\n]*",
                  "<checkout-or-user-tool-path>", text, flags=re.I)
    text = re.sub(r"D:[\\/]Program Files \(x86\)[^`\"\r\n]*",
                  "<python-installation>", text, flags=re.I)
    text = re.sub(r"C:[\\/]Users[\\/][^\\/\s`\"]+", "<user-profile>", text, flags=re.I)
    # Replace private lab addresses in historical documentation only. Program
    # code, API schema snapshots and deliberately synthetic test fixtures stay exact.
    import ipaddress
    def address(match):
        try:
            value = ipaddress.ip_address(match.group())
            if value.is_private and not value.is_loopback:
                return "192.0.2." + str(int(value) % 253 + 1)
        except ValueError:
            pass
        return match.group()
    text = re.sub(r"(?<![\w.])(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?![\w.])",
                  address, text)
    text = re.sub(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])",
                  "02:00:00:00:00:01", text)
    text = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                  "00000000-0000-4000-8000-000000000001", text)
    text = re.sub(r"(?i)\b(?:DESKTOP|LAPTOP)-[A-Z0-9]+\b", "EXAMPLE-HOST", text)
    return text


def build(output, root=ROOT):
    root, output = Path(root).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError("Snapshot destination must be new; no existing checkout is overwritten.")
    raw = subprocess.check_output(["git", "ls-files", "--cached", "--others",
                                   "--exclude-standard", "-z"], cwd=root)
    names = sorted({item.decode("utf-8") for item in raw.split(b"\0") if item})
    sources, transformed = {}, []
    # Do not inherit old Git history. Real local state is never in this new repository.
    for name in names:
        path = source_path(root, name)
        if name == "source-manifest.json" or not path.is_file():
            continue
        parts = set(Path(name).parts)
        if parts.intersection({".git", ".runtime", ".verification", ".local-backups", "node_modules",
                               ".venv"}) or any(name.startswith(prefix) for prefix in (
                                   "net-assistant/backend/data/", "net-assistant/backend/reports/",
                                   "net-assistant/backend/artifacts/", "net-assistant/backend/legacy_native/configs/")):
            raise ValueError(f"Private/generated state is tracked: {name}")
        if path.suffix.lower() in {".sqlite", ".db", ".pem", ".key", ".exe", ".dll"}:
            raise ValueError(f"Binary/private file unexpectedly in source: {name}")
        if ".local." in path.name or path.name.startswith(".env") and path.name != ".env.example":
            raise ValueError(f"Personal configuration unexpectedly in source: {name}")
        data = path.read_bytes()
        if re.search(rb"(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{40,})", data):
            raise ValueError(f"Credential-shaped token refused: {name}")
        if re.search(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{80,}", data):
            raise ValueError(f"Private key refused: {name}")
        sources[name] = digest(path)
    output.mkdir(parents=True)
    try:
        for name in sources:
            source, destination = root / name, output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if source.suffix.lower() in {".md", ".txt", ".json"} and not source.name.startswith("openapi-") and (
                    "docs" in source.parts or source.name == "README.md"):
                data = destination.read_bytes()
                try:
                    text = data.decode("utf-8-sig")
                except UnicodeDecodeError:
                    # Historical Windows console reports can be UTF-16/GBK.
                    # Normalize documentation only, never program code or schemas.
                    text = data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff"))
                                       else "gb18030", errors="replace")
                sanitized = sanitize_document(text).replace("\r\n", "\n").replace("\r", "\n")
                if sanitized != text or data != sanitized.encode("utf-8"):
                    destination.write_text(sanitized, encoding="utf-8", newline="\n")
                    transformed.append(name)
        inventory = {name: digest(output / name) for name in sources}
        manifest = {
            "format": 1, "app": "0.10.0", "files": inventory,
            "hash_normalization": "CRLF converted to LF for text files without NUL, matching Git checkout policy",
            "complete_current_source_files": len(inventory),
            "documentation_redactions_and_encoding_normalization": transformed,
            "all_program_code_copied_byte_for_byte": all(
                (root / name).read_bytes() == (output / name).read_bytes() for name in sources
                if Path(name).suffix.lower() in {".py", ".ps1", ".ts", ".tsx", ".css", ".html", ".cmd"}),
            "excluded": ["working databases and seed (private local delivery)",
                         "credentials, sessions, personal config, old Git history",
                         "generated dependencies and binaries (separate matching Release asset)",
                         "user-provided Nmap/Npcap (license prerequisite)"],
        }
        (output / "source-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return manifest
    except BaseException:
        # Preserve diagnostic contents; never advertise a failed candidate as complete.
        (output / "INCOMPLETE-SNAPSHOT").write_text("Snapshot failed; do not publish.", encoding="utf-8")
        raise


def verify(root=ROOT, *, require_git=False):
    root = Path(root).resolve()
    manifest = json.loads(source_path(root, "source-manifest.json").read_text("utf-8"))
    files = manifest["files"]
    if not files or manifest["complete_current_source_files"] != len(files):
        raise ValueError("Source inventory count differs from the manifest.")
    if (root / ".git").exists():
        raw = subprocess.check_output(["git", "ls-files", "--cached", "-z"], cwd=root)
        tracked = {name.decode("utf-8") for name in raw.split(b"\0") if name}
        tracked.discard("source-manifest.json")
        if tracked != files.keys():
            raise ValueError("Git and manifest file lists differ: " + ", ".join(sorted(tracked ^ files.keys())))
    elif require_git:
        raise ValueError("A Git checkout is required to verify the complete source inventory.")
    else:
        print("Warning: no Git metadata; inventory completeness was not checked.", file=sys.stderr)
    for name, expected in files.items():
        path = source_path(root, name)
        if not path.is_file() or digest(path) != expected:
            raise ValueError(f"Source fingerprint differs: {name}")
    print(f"All {len(files)} inventoried source files match.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--require-git", action="store_true",
                        help="fail --verify when Git metadata cannot prove inventory completeness")
    args = parser.parse_args()
    if args.verify:
        verify(require_git=args.require_git)
    elif args.output:
        value = build(args.output)
        print(f"Complete source candidate: {args.output.resolve()} ({len(value['files'])} files)")
    else:
        parser.error("Specify --output NEW_DIRECTORY or --verify")
