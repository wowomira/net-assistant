# 网维助手 · Net Assistant

面向授权网络环境的设备发现、资产管理与网络巡检项目。通过统一后端保存扫描证据、资产关联、监控与采集历史，并向前端提供 HTTP API。

**当前版本：`0.10.0`｜主要运行环境：Windows x64｜仓库：公开代码仓库**

本仓库包含后端、现有 React 工作台、数据库迁移、接口契约、测试和运行脚本。配套运行资源通过同仓库 Release 提供，不依赖项目原作者的盘符、用户名或个人软件安装目录。

> 当前是持续开发中的协作版本，不是全部规划功能均已完成的成品。后端认证与受控 SSH 能力已实现，前端仍是阶段性只读工作台，尚无正式登录页和网页 SSH 终端。

## 目录

- [功能与开发状态](#功能与开发状态)
- [架构与代码目录](#架构与代码目录)
- [快速开始](#快速开始)
- [工具、配置与数据](#工具配置与数据)
- [开发与前后端协作](#开发与前后端协作)
- [检查与测试](#检查与测试)
- [文档与安全边界](#文档与安全边界)

## 功能与开发状态

| 模块 | 当前能力 | 使用前提或边界 |
|---|---|---|
| 平台认证 | 用户、登录会话、角色与权限校验 | 首次运行自行创建账号，无默认管理员或默认密码 |
| 网络发现 | 基于 Nmap 的主机发现、端口与服务探测、证据保存 | 配置已授权的目标，自行准备 Nmap；部分探测需要 Npcap 和相应权限 |
| 资产台账 | 发现记录归并、资产关联、审计与身份判定历史 | 保留原始证据，不将端口号或缺失信息冒充确定结论 |
| 调度与监控 | 扫描调度、Gatus 监控及结果查询 | 显式配置并启用，默认不自动扫描或监控外部目标 |
| 网络采集 | Windows 本机网络、交换机 SNMP 与 mDNS 采集及历史查询 | 相关运行环境、网络可达性、授权与凭据就绪 |
| 网站观测 | HTTP 信息与受限制的静态截图 | 配套 Chromium 运行环境；并非任意交互网页的完整渲染 |
| 受控 SSH | 后端会话、目标授权及受控操作能力 | 配置自己的设备凭据和主机密钥；尚无网页终端 UI |
| Web 工作台 | React 页面、已有业务查询与 API 客户端 | 阶段性只读前端；正式登录、改密和会话失效交互待完善 |

具体操作与限制见[项目实际能力与操作边界](net-assistant/backend/docs/项目实际能力与操作边界.md)及[前端对接说明](net-assistant/backend/docs/前端对接说明.md)。

## 架构与代码目录

项目采用**前后端分离的源码组织和 HTTP 接口契约**：

```text
React / TypeScript 前端
        │ HTTP API + 登录 Cookie
        ▼
FastAPI 后端
├─ 认证与授权、受控终端
├─ 发现、资产、调度、监控
└─ 网络采集、交换机、网站观测
        │
        ├─ SQLite：业务数据、证据与历史
        └─ 外部工具／协议：Nmap、Gatus、SSH、SNMP、mDNS、Chromium
```

前端和后端可以独立开发，通过 OpenAPI 契约对接。推荐的本地入口由后端同源托管前端构建文件，便于处理 Cookie 与同源校验；这不意味着前端被写进了后端业务代码，也不要求协作者使用相同的电脑目录。

```text
仓库根目录
├─ net-assistant/
│  ├─ backend/
│  │  ├─ app/              后端 API 与业务模块
│  │  ├─ migrations/       数据库迁移
│  │  ├─ configs/          通用配置模板
│  │  ├─ scripts/          业务命令行与可选服务管理
│  │  ├─ legacy_native/    归档原生扫描实现，保留用于回归与恢复
│  │  ├─ docs/             OpenAPI、接口对接与业务说明
│  │  └─ tests/            后端测试
│  └─ frontend/            React / TypeScript 源码、测试与依赖锁文件
├─ scripts/                环境准备、统一启动、数据种子和交付工具
├─ tests/                  运行环境、数据导入与 HTTP 集成测试
├─ docs/                   协作、运行环境与验收说明
├─ .github/workflows/      Windows 源码与配套资源验证
├─ bootstrap.ps1           项目内运行环境与管理命令入口
├─ start.cmd               前台统一启动入口
├─ runtime.lock.json       配套资源版本、来源和校验值
├─ source-manifest.json    发布快照的源码校验清单
└─ .runtime/               本机环境、工具、配置、构建与数据，不纳入 Git
```

## 快速开始

### 1. 环境准备

- Windows 10/11 x64、64 位 Windows PowerShell。
- 已安装 Git，可访问 GitHub 或通过受控离线介质取得源码与资源。
- 建议预留至少 4 GB 磁盘空间。
- **无需预先全局安装 Python、Node.js 或 Go**；推荐流程使用配套资源中的项目内环境。

先克隆仓库，在后续所有步骤中保持位于仓库根目录：

```powershell
git clone https://github.com/wowomira/net-assistant.git
cd net-assistant
```

### 2. 下载并校验配套资源

从 [v0.10.0-collaboration.1 Release](https://github.com/wowomira/net-assistant/releases/tag/v0.10.0-collaboration.1) 下载 `runtime-resources-win-x64.zip`，放入仓库根目录。必须使用与当前 `runtime.lock.json` 匹配的资源，不要复制其他人的 `.venv`。

在 PowerShell 中校验后解压：

```powershell
$expected = (Get-Content -LiteralPath .\runtime.lock.json -Raw | ConvertFrom-Json).release.sha256
$actual = (Get-FileHash -LiteralPath .\runtime-resources-win-x64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw '资源包校验失败，禁止继续' }
Expand-Archive -LiteralPath .\runtime-resources-win-x64.zip -DestinationPath .
```

解压后应存在 `.runtime/resources/manifest.json`。资源包含固定版本的 Python、Node/npm、Python wheels、npm 离线缓存、Gatus、OpenSSH、Chromium headless shell 和本地 Swagger 资源，以及相应许可文件。

### 3. 初始化、建号并启动

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 init
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 create-user yourname --role admin
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 doctor
.\start.cmd
```

- 将 `yourname` 换为自己的用户名，在本机安全提示中输入密码，不把密码写进命令行或提交到 Git。
- 配套资源就绪后，`setup` 离线安装 Python/npm 依赖并构建前端。下载源码与资源本身仍需联网，或通过受控离线介质取得。
- `init` 在运行库不存在时创建；有校验通过的私人种子则导入历史，无种子则创建空库。已有库不会被覆盖、合并或重复灌入种子。
- `start.cmd` 启动 API 和明确启用的后台工作。默认不自动扫描、监控或采集，不安装系统服务、不修改防火墙。
- 保持启动窗口运行，使用 `Ctrl+C` 结束本次启动的工作；不会接管其他已运行服务。

`ExecutionPolicy Bypass` 仅作用于该次 PowerShell 进程，不永久修改系统策略，也不等于管理员或驱动授权。

### 4. 登录并打开工作台

默认本地地址：

| 入口 | 地址 |
|---|---|
| Swagger 接口文档与联调 | `http://127.0.0.1:8001/docs` |
| 现有 Web 工作台 | `http://127.0.0.1:8001/console/` |
| 当前服务 OpenAPI | `http://127.0.0.1:8001/openapi.json` |

由于尚无正式登录页面，开发期按以下方式联调：

1. 打开 `/docs`，展开 `POST /api/v1/auth/login`。
2. 点击 **Try it out**，填写刚创建的 `username` 和 `password`，执行登录。
3. 在**同一个浏览器、相同主机名和端口**打开 `/console/`，浏览器使用登录 Cookie 请求 API。

不要把 `127.0.0.1` 换成 `localhost` 或切换端口后假定会话仍然有效，也不要通过关闭认证解决登录问题。纯源码与运行资源首次启动没有真实设备数据是正常现象。

## 工具、配置与数据

### 扫描工具与设备授权

Nmap/Npcap 不包含在仓库或资源包中。扫描功能源码已保留，但需使用者从官方渠道自行取得程序、确认许可，并安装适用的驱动。

取得完整 Nmap 安装目录后，导入项目：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 import-nmap --source "你自己的完整Nmap目录"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 doctor
```

导入会复制 Nmap 程序、依赖、数据库、脚本和许可到 `.runtime/tools/nmap`，不修改原安装目录、不安装 Npcap、不覆盖已有导入目录。普通 TCP 探测与依赖原始包／驱动的探测权限不同；某些目标可能无法提供足够的 OS 或服务识别证据。

SSH 和 SNMP 使用自己的设备账号、密钥、主机密钥及协议凭据，资源包不提供这些访问权限。

### 每位协作者独立的运行状态

| 项目内位置 | 用途 |
|---|---|
| `.runtime/resources/` | 经过校验的 Release 原料 |
| `.runtime/python/`、`.runtime/tools/` | 项目内解释器、依赖及工具 |
| `.runtime/configs/` | 自己的扫描范围、调度、监控、采集和终端配置 |
| `.runtime/data/development.sqlite` | 自己的业务运行库 |
| `.runtime/frontend/` | 独立前端依赖与构建副本，不作为源码编辑入口 |
| `.runtime/seeds/` | 可选私人历史种子及清单，不上传 GitHub |

自动任务默认停用或没有目标。实际扫描、监控、交换机／本机采集必须先按[协作与离线运行指南](docs/Windows协作与离线运行.md)设置自己的授权目标，再显式启用。

**源码、运行资源和历史数据是三类不同内容。** Git clone 与 Release 资源包不包含真实历史、平台账号、设备凭据或个人配置。私人种子仅在另外获准提供时使用，历史观测时间不代表当前在线状态；启动不会自动恢复旧网段扫描。

## 开发与前后端协作

- **后端开发**：编辑 `net-assistant/backend/app/`；数据库变更通过迁移和临时库验证，不直接改写已有工作库。
- **前端开发**：编辑 `net-assistant/frontend/src/`，不要修改 `.runtime/frontend/src/`；后者会被构建流程同步。
- **接口契约**：以 `net-assistant/backend/docs/openapi-0.10.0.json` 和实际运行服务的 `/openapi.json` 为准。API 变更需同步契约、前端类型、测试及对接说明。
- **前端任务**：按[前端对接说明](net-assistant/backend/docs/前端对接说明.md)对接已有 API；正式登录、改密、会话失效及网页终端交互需继续开发，不另造演示数据接口替代真实后端。
- **本地联调**：优先使用快速开始的同源模式。现有 Vite 开发代理指向 `8000`，若单独开发前端并对接默认 `8001` 后端，需调整代理并核对登录请求的同源策略，不通过放宽认证或 CSRF 校验绕过问题。
- **团队协作**：每人独立 clone、独立运行库与账号，通过分支和 Pull Request 审阅，不共享 `.runtime` 或私钥。

如需使用系统 Python/Node 开发环境，已验证的固定基线为 **Python 3.13.7、Node.js 24.11.0／npm 11.6.1**。替代安装命令和提交规范见 [CONTRIBUTING.md](CONTRIBUTING.md)；不要将不同安装路线的环境混用。

## 检查与测试

完成推荐环境准备后，在仓库根目录执行：

```powershell
# 依赖、数据库结构与应用就绪检查，不扫描目标
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 check

# 交付／HTTP／后端／前端测试，以及类型检查和生产构建
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 test

# 自行准备 Nmap 和必要驱动／权限后，显式启用真实本地及回环工具测试
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 test --local-tools

# 检查交付快照源码指纹；开发修改后需重新生成对应清单
.\.runtime\python\python.exe .\scripts\collaboration_snapshot.py --verify
```

缺少工具或未显式启用时，相关测试会说明跳过原因；跳过不算真实工具验证通过。源码清单用于核对交付内容，开发后出现指纹变化不等于代码丢失。

仓库包含源码安装和配套资源重建两条 Windows CI。实际测试证据、离线重建范围及未验收事项见[交付验收报告](docs/GitHub协作交付验收-2026-11-16.md)和具体 Actions 运行记录；CI 不替代真实厂商设备或第二台实体 Windows 的验收。

## 文档与安全边界

| 文档 | 适合查阅的内容 |
|---|---|
| [Windows 协作与离线运行](docs/Windows协作与离线运行.md) | 资源下载、配置、工具导入、运行与授权前提 |
| [前端对接说明](net-assistant/backend/docs/前端对接说明.md) | 前端接口、认证、类型与联调约定 |
| [后端程序功能与采集数据说明](net-assistant/backend/docs/后端程序功能与采集数据说明.md) | 后端模块职责与数据内容 |
| [项目实际能力与操作边界](net-assistant/backend/docs/项目实际能力与操作边界.md) | 能力限制与操作条件 |
| [工具与运行环境](docs/工具与运行环境.md) | 外部工具及环境说明 |
| [GitHub 协作交付验收](docs/GitHub协作交付验收-2026-11-16.md) | 验证证据与未测试范围 |
| [团队协作](CONTRIBUTING.md) | 分支、接口变更、迁移与提交流程 |
| [安全说明](SECURITY.md) | 凭据、数据与安全问题处理 |

- **仅对已授权的网络与设备执行探测、采集或终端操作。** 历史数据不是新环境的扫描授权。
- 不提交真实数据库、设备凭据、私钥、会话、本机配置、截图证据或运行缓存；公开仓库不得包含这些内容。
- 默认入口只监听本机回环地址，使用本地 HTTP 联调。网络部署所需的 HTTPS、代理、防火墙和正式登录交互需另行配置并验收。
- 不因启动问题关闭认证、CSRF、SSH 主机密钥校验或系统防护。
- 第三方工具遵守各自许可证；资源包保留相应许可及来源。自有源码的开源许可证尚未选定；本次仅调整仓库可见性，不新增许可证。
