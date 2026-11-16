"""Export persisted measurements and compare compatible historical scans."""
import ipaddress
import json
from pathlib import Path

from app.discovery.store import Database
from app.discovery.config import address_sort_key


def compare_snapshot(snapshot: dict) -> dict:
    previous = snapshot["previous"]
    result = {
        "status": "unavailable", "reason_code": "no_previous_job",
        "baseline_job_id": previous["job"]["id"] if previous else None,
        "added_addresses": [], "not_observed_addresses": [],
        "mac_changes": [], "probe_changes": [],
    }
    if previous is None:
        return result
    current_job, previous_job = snapshot["job"], previous["job"]
    # 不完整扫描不能用缺失记录推断设备或端口变化。
    if current_job["state"] != "completed" or previous_job["state"] != "completed":
        return {**result, "reason_code": "incomplete_scan"}
    if current_job["config_snapshot"] != previous_job["config_snapshot"]:
        return {**result, "reason_code": "configuration_changed"}

    before_hosts = {row["address"]: row for row in previous["hosts"]}
    after_hosts = {row["address"]: row for row in snapshot["hosts"]}
    result.update(
        status="available", reason_code=None,
        added_addresses=sorted(after_hosts.keys() - before_hosts.keys(), key=address_sort_key),
        not_observed_addresses=sorted(before_hosts.keys() - after_hosts.keys(), key=address_sort_key),
    )
    for address in sorted(before_hosts.keys() & after_hosts.keys(), key=address_sort_key):
        before, after = before_hosts[address]["mac"], after_hosts[address]["mac"]
        if before != after:
            result["mac_changes"].append({"address": address, "before": before, "after": after})

    def probe_key(row):
        return row["address"], row["phase"], row["method"], row["port"]

    def value(row):
        # 时延的自然波动不算配置/服务变化；服务证据保留原始可核对字段。
        if row["method"] == "screenshot":
            # New artifact IDs and transferred byte counts do not mean a site changed.
            # Visual image comparison is deliberately not implemented.
            return {"status": row["status"], "evidence": {
                key: row["evidence"][key] for key in ("scheme", "renderMode") if key in row["evidence"]
            }}
        return {"status": row["status"], "evidence": (
            row["evidence"] if row["phase"] == "enrichment" else {}
        )}

    before_probes = {probe_key(row): row for row in previous["probes"]}
    after_probes = {probe_key(row): row for row in snapshot["probes"]}
    for key in sorted(before_probes.keys() & after_probes.keys(),
                      key=lambda key: (address_sort_key(key[0]), key[1], key[2], key[3] or 0)):
        before, after = value(before_probes[key]), value(after_probes[key])
        if before != after:
            address, phase, method, port = key
            result["probe_changes"].append({
                "address": address, "phase": phase, "method": method, "port": port,
                "before": before, "after": after,
            })
    return result


def _cell(value):
    # 网络和人工字段均当作文本，禁止换行、竖线或 HTML 破坏导出表格。
    text = "" if value is None else str(value)
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "&#124;").replace("\r", " ").replace("\n", " "))


def _table(headings, rows):
    return [
        "| " + " | ".join(map(_cell, headings)) + " |",
        "| " + " | ".join("---" for _ in headings) + " |",
        *["| " + " | ".join(map(_cell, row)) + " |" for row in rows],
    ]


def write_report(db: Database, job_id: str, directory: Path) -> Path:
    snapshot = db.scan_snapshot(job_id)
    if snapshot is None:
        raise ValueError("Unknown discovery job.")
    job, hosts, probes = snapshot["job"], snapshot["hosts"], snapshot["probes"]
    comparison = compare_snapshot(snapshot)
    directory = Path(directory).resolve() / job_id
    directory.mkdir(parents=True, exist_ok=False)
    exported = {"job": job, "hosts": hosts, "probes": probes, "comparison": comparison}
    (directory / "observations.json").write_text(
        json.dumps(exported, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# 扫描结果", "",
        *_table(["任务", "状态", "开始（UTC）", "结束（UTC）"], [
            [job["id"], job["state"], job["started_at"], job["finished_at"]]]),
        "", "## 扫描配置", "",
        *_table(["字段", "值"], [
            [key, json.dumps(value, ensure_ascii=False)] for key, value in job["config_snapshot"].items()
        ]),
        "", "## 执行统计", "",
        *_table(["字段", "值"], [
            [key, json.dumps(value, ensure_ascii=False)] for key, value in job["coverage"].items()
        ]),
        "", "## 发现记录", "",
        *_table(["地址", "网络名称", "名称来源", "MAC", "响应类型", "开放 TCP", "观测时间（UTC）", "资产编号"], [
            [row["address"], row["hostname"], row["hostname_source"], row["mac"],
             row["confidence"], ", ".join(map(str, row["open_ports"])),
             row["observed_at"], row["asset_id"]] for row in hosts
        ]),
        "", "## TCP 覆盖", "",
        *_table(["地址", "范围", "计划", "已尝试", "拒绝", "超时", "不可达", "错误", "未尝试"], [
            [host["address"], *[host["port_scan"][field] for field in
             ("scope", "planned", "attempted", "refused", "timeout", "unreachable", "error", "unattempted")]]
            for host in hosts
        ]),
        "", "## 服务", "",
        *_table(["地址", "TCP 端口", "协议", "产品声明", "版本声明", "识别", "端口提示", "证据方法"], [
            [host["address"], service["port"], service["protocol"], service["product"], service["version"],
             service["identification"], service["port_hint"], ", ".join(service["evidence_methods"])]
            for host in hosts for service in host["services"]
        ]),
        "", "## 网站", "",
        *_table(["地址", "入口", "状态", "HTTP", "标题", "Server", "跳转目标", "TLS", "截图状态", "截图时间（UTC）"], [
            [host["address"], site["url"], site["status"], site["status_code"], site["title"], site["server"],
             site["redirect_location"], site["tls_status"], site["screenshot"]["status"],
             site["screenshot"]["captured_at"]]
            for host in hosts for site in host["websites"]
        ]),
        "", "## 历史比对", "",
        *_table(["状态", "基线任务", "原因码"], [
            [comparison["status"], comparison["baseline_job_id"], comparison["reason_code"]]]),
        "", *_table(["地址变化", "地址"], [
            *[["新增观测", address] for address in comparison["added_addresses"]],
            *[["本次未观测", address] for address in comparison["not_observed_addresses"]],
        ]),
        "", *_table(["地址", "原 MAC", "本次 MAC"], [
            [row["address"], row["before"], row["after"]] for row in comparison["mac_changes"]
        ]),
        "", *_table(["地址", "阶段", "方法", "端口", "原结果", "本次结果"], [
            [row["address"], row["phase"], row["method"], row["port"],
             json.dumps(row["before"], ensure_ascii=False),
             json.dumps(row["after"], ensure_ascii=False)] for row in comparison["probe_changes"]
        ]),
        "", "## 探测记录", "",
        *_table(["地址", "阶段", "方法", "端口", "状态", "耗时 ms", "原因码", "观测时间（UTC）", "证据"], [
            [row["address"], row["phase"], row["method"], row["port"], row["status"],
             row["duration_ms"], row["reason_code"], row["observed_at"],
             json.dumps(row["evidence"], ensure_ascii=False)] for row in probes
        ]),
    ]
    (directory / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return directory
