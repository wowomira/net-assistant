"""Package only inventoried redistributable resources; never runtime data or Nmap."""
import hashlib
import json
from pathlib import Path
import zipfile

from runtime_support import ROOT, safe_relative, verify_resources


def package(root=ROOT):
    root = Path(root).resolve()
    resources = root / ".runtime/resources"
    lock_path = root / "runtime.lock.json"
    lock = json.loads(lock_path.read_text("utf-8"))
    manifest = verify_resources(resources, lock["resource_manifest_sha256"])
    for name in manifest["files"]:
        if any(part in {"nmap", "seeds", "data", "configs"} for part in safe_relative(name).parts):
            raise ValueError("Private/user-provided data must never enter the resource archive.")
    delivery = root / ".runtime/delivery"
    delivery.mkdir(parents=True, exist_ok=True)
    target = delivery / "runtime-resources-win-x64.zip"
    if target.exists():
        raise ValueError("Delivery archive already exists; choose a new release rather than overwrite it.")
    temporary = target.with_suffix(".partial")
    try:
        with zipfile.ZipFile(temporary, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name in ["manifest.json", *sorted(manifest["files"])]:
                path = resources / name
                archive.write(path, ".runtime/resources/" + name)
        temporary.rename(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    with target.open("rb") as file:
        lock["release"]["sha256"] = hashlib.file_digest(file, "sha256").hexdigest()
    lock["release"]["bytes"] = target.stat().st_size
    lock_path.write_text(json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Resource archive: {target} ({target.stat().st_size} bytes)")
    print("SHA256: " + lock["release"]["sha256"])
    print("Contains no seed, database, accounts, personal config, Nmap or Npcap.")
    return target


if __name__ == "__main__":
    package()
