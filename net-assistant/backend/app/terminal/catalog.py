"""Version-bounded operator-approved templates, never an arbitrary CLI interpreter.

Syntax here is reference material pending actual model/firmware validation. An enrolled
target must explicitly confirm compatibility AND allow each command before execution.
These flags are operator declarations, not evidence of our real-device verification.
"""
import re
from app.discovery.api import ApiError

VENDORS = [
    {"id": "ruijie", "name": "锐捷", "platform": "rgos"},
    {"id": "cisco", "name": "Cisco", "platform": "ios"},
    {"id": "huawei", "name": "华为", "platform": "vrp"},
    {"id": "h3c", "name": "H3C", "platform": "comware"},
]

COMMANDS = {
    "version": ("查看版本", "query", "low", {}),
    "interfaces": ("接口摘要", "query", "low", {}),
    "vlans": ("查看VLAN", "query", "low", {}),
    "mac_table": ("查看MAC表", "query", "low", {}),
    "lldp": ("查看LLDP邻居", "query", "low", {}),
    "interface_description": ("修改接口描述", "configuration", "normal",
                              {"interface": "interface", "description": "description"}),
    "port_shutdown": ("关闭端口（可能中断管理连接）", "configuration", "high", {"interface": "interface"}),
    "port_enable": ("启用端口", "configuration", "normal", {"interface": "interface"}),
    "vlan_create": ("创建VLAN", "configuration", "normal", {"vlanId": "vlan"}),
    "vlan_delete": ("删除VLAN（可能中断业务）", "configuration", "high", {"vlanId": "vlan"}),
    "save_configuration": ("保存配置（仅参考，额外交互尚未支持）", "reference", "high", {}),
    "reboot": ("重启设备（仅参考，不允许执行）", "reference", "high", {}),
    "factory_reset": ("恢复出厂（仅参考，不允许执行）", "reference", "high", {}),
}

QUERIES = {
    "cisco": ["show version", "show interfaces status", "show vlan", "show mac address-table", "show lldp neighbors"],
    "ruijie": ["show version", "show interfaces status", "show vlan", "show mac-address-table", "show lldp neighbors"],
    "huawei": ["display version", "display interface brief", "display vlan", "display mac-address", "display lldp neighbor brief"],
    "h3c": ["display version", "display interface brief", "display vlan", "display mac-address", "display lldp neighbor-information"],
}
QUERY_IDS = ["version", "interfaces", "vlans", "mac_table", "lldp"]


def catalog(vendor=None, target=None):
    if vendor is not None and vendor not in QUERIES:
        raise ApiError(422, "unsupported_vendor", "不支持该厂商目录。")
    result = []
    for command_id, (label, category, risk, params) in COMMANDS.items():
        result.append({
            "id": command_id, "name": label, "category": category, "risk": risk,
            "modifiesConfiguration": category == "configuration",
            "requiresDoubleConfirmation": risk == "high",
            "parameters": [{"name": name, "type": kind, "required": True,
                            "minimum": 1 if kind == "vlan" else None,
                            "maximum": 4094 if kind == "vlan" else None}
                           for name, kind in params.items()],
            "verificationStatus": "reference_unverified",
            "realDeviceVerified": False,
            "executable": bool(target and target.compatibility_confirmed and
                               command_id in target.allowed_commands and category != "reference"),
            "executionMode": "privileged_exec" if vendor in ("cisco", "ruijie") else "user_view",
            "automaticSave": False,
        })
    return result


def render(target, command_id, parameters):
    if command_id not in COMMANDS:
        raise ApiError(422, "unknown_command", "不支持任意原始命令，请使用命令目录。")
    _, category, risk, spec = COMMANDS[command_id]
    if category == "reference":
        raise ApiError(409, "reference_only", "该命令仅供参考，尚不支持受控执行。")
    if set(parameters) != set(spec):
        raise ApiError(422, "command_parameters_invalid", "命令参数必须与目录完全一致。")
    clean = {}
    for name, kind in spec.items():
        value = parameters[name]
        valid = (
            kind == "vlan" and type(value) is int and 1 <= value <= 4094 or
            kind == "interface" and isinstance(value, str) and
            re.fullmatch(r"[A-Za-z][A-Za-z0-9/.-]{0,47}", value) or
            kind == "description" and isinstance(value, str) and
            re.fullmatch(r"[A-Za-z0-9 _./:-]{1,80}", value)
        )
        if not valid:
            raise ApiError(422, "command_parameters_invalid", "参数包含不允许的字符或超出范围。")
        clean[name] = value
    if not target.compatibility_confirmed or command_id not in target.allowed_commands:
        raise ApiError(409, "command_not_enabled", "此设备尚未确认兼容或没有启用该命令。")
    if command_id in QUERY_IDS:
        return [QUERIES[target.vendor][QUERY_IDS.index(command_id)]], risk
    cisco_style = target.vendor in ("cisco", "ruijie")
    enter, leave = ("configure terminal", "end") if cisco_style else ("system-view", "return")
    body = []
    if "interface" in clean:
        body.append("interface " + clean["interface"])
    if command_id == "interface_description":
        body.append("description " + clean["description"])
    elif command_id == "port_shutdown":
        body.append("shutdown")
    elif command_id == "port_enable":
        body.append("no shutdown" if cisco_style else "undo shutdown")
    elif command_id == "vlan_create":
        body.append(f"vlan {clean['vlanId']}")
    elif command_id == "vlan_delete":
        body.append(("no vlan " if cisco_style else "undo vlan ") + str(clean["vlanId"]))
    return [enter, *body, leave], risk
