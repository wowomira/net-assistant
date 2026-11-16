"""Opt-in read-only HTTP/build smoke test; no network target probing."""

import json
from pathlib import Path
import re
import sqlite3
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8000"
OPENER = build_opener(ProxyHandler({}))
TABLES = ("discovery_jobs", "discovery_probes", "assets", "asset_discovery_links",
          "asset_audit_events", "scheduled_scan_runs")


def counts():
    path = (ROOT / "data/inspection.sqlite").resolve()
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        return {table: connection.execute(f"select count(*) from {table}").fetchone()[0]
                for table in TABLES}


def get(path):
    with OPENER.open(BASE + path, timeout=15) as response:
        return response.status, response.read(), dict(response.headers)


def catalog(path):
    items = []
    cursor = None
    seen = set()
    while True:
        query = "?limit=200" + (f"&cursor={cursor}" if cursor else "")
        _, body, headers = get(path + query)
        assert headers.get("cache-control") == "no-store"
        data = json.loads(body)
        items.extend(data["items"])
        cursor = data["nextCursor"]
        if cursor is None:
            return items
        assert cursor not in seen, "repeated cursor"
        seen.add(cursor)


def main():
    before = counts()
    _, html, _ = get("/console/")
    text = html.decode("utf-8")
    assert "网维助手" in text
    assets = re.findall(r'(?:src|href)="(/console/assets/[^"]+)"', text)
    assert len(assets) == 2
    for path in assets:
        assert get(path)[0] == 200
    rows = catalog("/api/v1/assets")
    jobs = catalog("/api/v1/discovery-jobs")
    _, body, _ = get("/api/v1/scheduler")
    scheduler = json.loads(body)
    for path in ("/api/progress", "/api/v1/no-such-api", "/console/src/App.tsx",
                 "/console/data/inspection.sqlite", "/console/%2e%2e/backend/data/inspection.sqlite"):
        try:
            get(path)
            raise AssertionError("must not be served: " + path)
        except HTTPError as error:
            assert error.code == 404, (path, error.code)
    for asset in rows:
        catalog(f"/api/v1/assets/{asset['id']}/observations")
        catalog(f"/api/v1/assets/{asset['id']}/audit")
        assert asset["hostMetrics"] is None
    latest = max(jobs, key=lambda job: job["startedAt"])
    hosts = catalog(f"/api/v1/discovery-jobs/{latest['id']}/hosts")
    probes = catalog(f"/api/v1/discovery-jobs/{latest['id']}/probes")
    after = counts()
    assert before == after, "business rows changed during read-only verification; inspect cause"
    print(json.dumps({
        "evidence": "actual_local_http_get_not_browser_screenshot",
        "source": BASE, "staticAssets": assets,
        "businessCountsBefore": before, "businessCountsAfter": after,
        "assets": len(rows), "jobs": len(jobs), "latestJobId": latest["id"],
        "latestHostSnapshots": len(hosts), "latestProbeRecords": len(probes),
        "todayStatus": scheduler["todayStatus"], "workerState": scheduler["worker"]["state"],
        "scanTriggered": False,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
