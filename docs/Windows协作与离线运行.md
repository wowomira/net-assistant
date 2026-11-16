# Windows 协作与离线运行

## 交付定义

目标是让协作者得到 **0.10.0 现有实现**，而不是承诺所有规划功能均已实现。
后端登录/授权、受控 SSH、Nmap 发现和探测、资产台账、调度、Gatus 监控、
Windows 本机网络采集、交换机 SNMP、mDNS、网站静态截图、API 和阶段性 React 工作台均保留。
正式登录页面和网页 SSH 终端 UI 原本没有，不把它们说成迁移时丢失，也不宣称本轮已经制作。

“前端入口框架”指现有 React 工作台的导航、页面与 API 客户端，不是把后端伪装成前端。
前后端源码独立，按 HTTP/OpenAPI 契约对接；生产构建可由后端同源托管，避免 Cookie/CORS
配置分歧。这仍允许朋友单独开发前端，不需要两个项目在代码内部“钩”在一起。

## 三类内容，边界不同

| 交付 | 包含 | 不包含 |
|---|---|---|
| Git 私人仓库 | 全部当前源码、7个迁移文件、前端锁文件、后端固定依赖、配置模板、契约、测试、说明、启动/快照/数据种子工具 | 原工作库、账号、会话、密钥、本机配置、旧 Git 历史、生成缓存 |
| 同仓库私人 Release 资源包 | Python 3.13.7 x64、Node 24.11.0/npm、wheels、npm缓存、Gatus v5.38.0及源代码/许可、OpenSSH 9.5.0.0p1-Beta、Playwright 1.65.2对应 Chromium headless shell 1255、Swagger 5.30.2、第三方许可和校验清单 | Nmap/Npcap、真实历史数据库、运行配置与账号 |
| 本地私人历史包 | 2026-11-16固定历史数据种子及其清单 | 账号、会话、终端操作、自动扫描授权，不上传 GitHub |

OpenSSH 选择与原系统客户端相同的 9.5 系列，而不是未经实测升级到新 Preview；
这是上游便携发行包的 Beta 标识，不把它冒充最新稳定版。第三方版本应后续单独做安全更新评估，
本次先以精确版本复现，不能把“固定版本”理解为永久安全。

## 协作者首次准备

要求：Windows 10/11 x64、64位 Windows PowerShell、足够磁盘空间（建议预留4GB以上）。
不要求 Python、Node、Go 已全局安装。
先由仓库所有者邀请你的 GitHub 账号访问私人仓库；没有擅自邀请任何人。

在你选择的目录克隆：

```powershell
git clone https://github.com/wowomira/net-assistant-collaboration.git
cd net-assistant-collaboration
```

在仓库网页 Release 下载 `v0.10.0-collaboration.1` 的 `runtime-resources-win-x64.zip`。
安装并登录 GitHub CLI 的用户也可以：

```powershell
gh release download v0.10.0-collaboration.1 --repo wowomira/net-assistant-collaboration --pattern runtime-resources-win-x64.zip
$expected = (Get-Content -LiteralPath .\runtime.lock.json -Raw | ConvertFrom-Json).release.sha256
if ((Get-FileHash -LiteralPath .\runtime-resources-win-x64.zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw '资源包校验失败，禁止继续'
}
Expand-Archive -LiteralPath .\runtime-resources-win-x64.zip -DestinationPath .
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 init
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 create-user yourname --role admin
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 check
.\start.cmd
```

`ExecutionPolicy Bypass` 只用于这次脚本进程，不永久改系统策略；这不是管理员授权或驱动许可。
SmartScreen、杀软、UAC及驱动安装是不同机制，不应不看来源就一律“允许”，也不需要关闭防护软件。

资源已下载后，`setup` 的 pip 和 npm 明确离线；不会偷偷从个人软件目录补齐缺失依赖。
包不匹配、文件损坏、缺少依赖或构建失败会停止，不写完成标记。
重复 `init` 不清库，重复启动不重灌历史，配置生成不覆盖你已有的设置。
纯源码 + 公共资源初次 `init` 是空业务库，真实实验数据按本地私人种子另行提供；这是数据隔离，
不是删除发现、台账或采集代码。

## 工具、驱动和授权

### Nmap / Npcap

自行从 Nmap/Npcap 官方渠道取得并确认许可。不从本项目下载、自动接受驱动许可，
也不将作者个人安装目录或 Windows 系统程序直接打包。
完整安装目录必须有 `nmap.exe`、DLL、`nmap-services`、`nmap-service-probes`、
`nmap-os-db`、`nmap-mac-prefixes`、`nmap-protocols`、LICENSE 等。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 import-nmap --source "你自己的完整Nmap目录"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 doctor
```

导入后使用 `.runtime/tools/nmap`；不修改原安装目录、不安装驱动、不覆盖已有导入目录。
本轮本机回归基线是 Nmap 7.92；采用其他版本需复核 XML/驱动/权限与探测差异，
不能因“命令能启动”就声称所有设备结果一致。
OS 指纹依赖适合的目标响应和原始探测权限，本来就可能返回 limited/no_match，不能伪造成识别成功。

### Windows PowerShell

系统组件经 Windows 的 SystemRoot 定位，这是操作系统前提，不是作者路径依赖。
本机采集默认关闭；明确启用才会读取你这台电脑的网卡、地址、邻居等信息。

### SSH / SNMP

SSH 客户端随资源包提供，但不会提供设备私钥、账号授权、known_hosts 或登录密码。
按已有受控终端文档配置自己的私钥与严格主机密钥，不关闭校验、不自动信任陌生设备。
SNMP 的授权范围和凭据由你自行配置，历史记录不构成新设备授权。

## 配置与单入口

你的运行设置都在 `.runtime/configs`，不入 Git：

| 文件 | 启用条件/作用 |
|---|---|
| `scope.local.json` | 手动或调度扫描范围；默认仅回环示例，真正使用前设置自己的授权网段/源地址/端口 |
| `daily-scan.local.json` | `enabled: true` 才启动调度；数据库必须仍指向本运行库 |
| `monitoring.local.json` | 非空且通过授权校验的 `endpoints` 才启动项目内 Gatus |
| `switches.local.json` | `enabled: true` 且授权/凭据就绪才启动交换机采集 |
| `terminal.local.json` | 受控目标和用户权限；不自动生成设备凭据 |
| `collection.local.json` | 自己创建，`enabled: true` 才按间隔采集本机网络 |

本机采集设置示例（`device_id` 用 PowerShell `[guid]::NewGuid()` 生成一次后固定使用，
不能填作者历史设备 ID、不能每次随机变化）：

```json
{
  "enabled": true,
  "device_id": "00000000-0000-4000-8000-000000000001",
  "label": "我自己的Windows主机",
  "interval_seconds": 300
}
```

示例 UUID 仅说明格式，请替换。统一入口 `start.cmd` 启动前检查账号、数据库、端口和启用配置，
不会抢占8000旧服务、安装 Windows 服务、开放防火墙或终止不属于自己的进程。
某个已启用工作线程失败会终止本次统一启动并报告，不让一个静默死亡的工作线程冒充正常运行。
本机 HTTP 固定回环；网络部署的 HTTPS/代理/防火墙须另外验收。

原 SCM 服务安装脚本仍完整保留，使用其原有独立 backend `.venv` 部署规则。
本次统一入口没有接管旧服务，也没有声称在第二台电脑验证过 SCM 安装。

## 目录模型

```text
仓库根
├─ bootstrap.ps1 / start.cmd        项目内环境准备 / 统一启动
├─ runtime.lock.json                版本、来源、资源清单/二进制哈希、Release对应关系
├─ source-manifest.json             发布快照逐文件哈希（提交后开发有修改则自然变化）
├─ scripts/
│  ├─ workspace.py                 数据库、建号、启动、检查、测试、历史种子命令
│  ├─ runtime_support.py            离线解包、哈希校验、项目内环境
│  ├─ runtime_manager.py            前台工作线程管理、用户Nmap导入
│  ├─ collaboration_snapshot.py     不修改源Git索引的干净源码快照/验证
│  ├─ package_resources.py          白名单资源打包，禁止私库/Nmap进入
│  └─ data_seed.py / verify_seed_http.py
├─ net-assistant/backend/
│  ├─ app/                         认证/终端/发现/台账/采集/监控/调度/SNMP/API
│  ├─ migrations/                  全部数据库迁移
│  ├─ configs/                     不带私人凭据的通用模板
│  ├─ scripts/                     原命令行和可选服务工具
│  ├─ legacy_native/               归档原生扫描代码，不偷换当前Nmap引擎
│  ├─ docs/                        OpenAPI及前端对接、能力边界
│  └─ tests/                       后端回归与真实工具选择性测试
├─ net-assistant/frontend/          React/TS源码、接口类型、测试、锁文件
├─ tests/                          启动、种子、真实HTTP和便携交付安全测试
└─ .runtime/                       忽略于Git；每个人自己的环境和数据
   ├─ resources/                   Release原料（含不可变清单）
   ├─ python/                      可重定位嵌入式解释器及依赖，无pyvenv.cfg
   ├─ tools/                       node/gatus/openssh/browsers/swagger/用户nmap
   ├─ frontend/                    独立前端依赖与构建
   ├─ configs/                     自己的设置
   ├─ data/                        自己的业务库、监控库
   └─ seeds/                       可选私人历史种子，不上传
```

## 验证与限制

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 test
# 自行准备Nmap/驱动权限后，显式运行回环真实工具回归：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 test --local-tools
.\.runtime\python\python.exe .\scripts\collaboration_snapshot.py --verify
```

必须分别记录：源码完整性、自动化测试、实际工具、不同路径离线重建、真实设备、干净第二台 Windows。
同一电脑的临时副本不等于第二台干净 Windows；未接入真实厂商设备，不声称所有型号都通过。
相同业务功能不意味着跨网络仍扫出作者相同的 IP/设备，这是授权范围、网络可达性和数据来源的差异。

## 第三方与隐私

资源清单记录 SHA256 和来源；保留各第三方许可证、Gatus 源码及依赖许可文本。
没有替自有源码擅自选开源许可证；私人仓库不等于可以不遵守第三方许可。
Nmap/Npcap 明确排除，不用用户 UAC 同意来代替再分发许可。
旧文档中个人安装路径和真实内网地址在发布快照里脱敏，代码逐字节核对，原件在本地备份保留。
仓库成员通过私有 Release 取得非敏感运行资源；真实历史和凭据不上传。
