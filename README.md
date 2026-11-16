# 网维助手｜0.10.0 后端协作版

以 2026-11-16 最后一次讨论的后端为基准：平台登录、受控 SSH、发现、台账、采集、调度和 API。
现有 React 工作台仍是阶段性只读前端，**没有正式登录页或 SSH 终端 UI**。
这不是所有规划功能都已完成的产品。根目录对应 `project`，不对应外层比赛资料目录。

## GitHub 协作与项目内运行（优先使用）

新协作仓库采用**完整源码 + 同版本私人 Release 资源包**：
源码保留后端、前端、全部迁移/接口契约/测试/配置模板，资源包提供项目内的 Python、
Node/npm、Python wheels、npm 离线缓存、Gatus、OpenSSH、Chromium headless shell 和 Swagger。
不要复制作者旧 `.venv`，也不需要作者的盘符、用户名、Python 安装路径或 Edge。

1. 克隆私人仓库；下载同仓库 `v0.10.0-collaboration.1` Release 的
   `runtime-resources-win-x64.zip`，按 `runtime.lock.json` 的 SHA256 核对，解压到仓库根。
2. 运行以下命令（不要求系统 Python、Node 或 Go）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 init
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 create-user yourname --role admin
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 doctor
.\start.cmd
```

`setup` 只从配套资源重建，Python 和 npm 均离线安装，前端在本地重新构建。
`start.cmd` 是前台统一入口：API，以及**你明确启用的**扫描调度、监控、交换机/本机采集；
默认不扫描任何原作者网段，不自动装服务、不修改防火墙。`Ctrl+C` 结束自己启动的工作。

**外部明确前提仍存在：Windows x64、授权范围、设备凭据，以及 Nmap/Npcap 的官方安装/许可和驱动权限。**
Nmap/Npcap 不由本仓库重分发，不代表删除扫描功能。
自行取得完整 Nmap 后执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 import-nmap --source "你自己的完整Nmap目录"
```

它复制 EXE、DLL、数据库、脚本与许可到 `.runtime/tools/nmap`，之后不再依赖其原安装路径。
Npcap 仍需本人从官方渠道安装、同意许可，某些原始探测需相应权限；普通 TCP 扫描和
需要驱动的 OS/原始包能力不能混为一谈。

详细步骤、GitHub 下载命令、配置位置及验收边界见
`docs/Windows协作与离线运行.md`。`source-manifest.json` 是发布快照的逐文件校验清单，
`runtime.lock.json` 对应同版本的资源包。

### 另一条路径：系统 Python/Node 的开发者安装

支持基线：**Windows x64 / Python 3.13.7 / Node.js 24.11.0（npm 11.6.1）**。
先自行安装这组固定版本；不能仅凭同属 Node 24 就假定新 npm 对锁文件的行为相同。
在本 README 所在的仓库根目录运行：

```powershell
python scripts/workspace.py doctor
python scripts/workspace.py setup --index-url https://pypi.org/simple
python scripts/workspace.py init
python scripts/workspace.py create-user yourname --role admin
python scripts/workspace.py serve
```

- `setup` 新建 `.runtime/venv`，安装固定依赖，`npm ci` 后构建到 `.runtime/frontend/dist`，需要联网。
- `init` 在运行库不存在时初始化 `.runtime/data/development.sqlite`：本地包有通过校验的历史数据种子时预装历史，没有种子时创建空库。已有运行库只检查，不覆盖或合并；不读取原作者工作库，不创建默认管理员。
- 创建账号时在本机安全提示中输入两次 12–128 字符密码，不把密码放进命令或聊天。
- `serve` 显式启用**回环 HTTP 开发模式**，固定 `127.0.0.1:8001`，可用 `--port` 改端口但不可改监听地址。
- 不覆盖旧 `.venv`、旧数据库、正式前端 `dist` 或现有 Windows 服务，不安装服务或修改防火墙。
- 生成的扫描/交换机配置默认停用，监控/SSH 目标为空；预装历史不启用原网段扫描或自动采集。纯源码环境没有数据种子时，页面没有设备数据是正常现象。

### 本地历史数据已预装（2026-11-16）

本机独立运行库现在已有真实历史：5次扫描、10条发现、11,165条探测、2个资产和133条网络采集记录。
快照窗口为北京时间 **2026-11-16 15:22:09.980—15:22:10.119**。它是历史快照，不是持续同步，也不代表设备当前在线。

- `.runtime/seeds/inspection-seed.sqlite`：通过当前结构重新生成的只读用途数据种子，附清单及校验值。
- `.runtime/data/development.sqlite`：已导入数据的独立运行库，继续新增数据使用此库，启动不重新灌入种子。
- 没有默认账号；仍需运行上面的 `create-user` 创建自己的管理员，再启动 `serve`。
- 原工作库、既有服务及配置未切换。真实数据和环境留在项目目录内，但被 Git 忽略；**纯源码 ZIP / Git clone 不会自动带上这些数据**。
- 重新打本地完整交付包时要保留数据种子及其清单；禁止把它们加入公开源码包或上传。

详情、命令及验收边界见 `docs/历史数据预装与验收-2026-11-16.md`。本次仅完成数据预装，尚未完成无需系统 Python/Node 的便携运行改造。

### 开发期怎样登录

打开 `http://127.0.0.1:8001/docs`，展开 `POST /api/v1/auth/login`，点 Try it out，
填写自己创建的 `username` 和 `password` 后 Execute。然后在**同一个浏览器、相同主机名和端口**
打开 `http://127.0.0.1:8001/console/`。Cookie 随同源 API 请求发送。
不要换成 `localhost` 或另一端口，也不要用关闭鉴权来替代登录。

这是后端联调流程，**不是正式登录 UI**。项目内便携入口使用本地 Swagger 资源，
不需要 CDN；旧开发者入口在没有本地资源时仍保留原行为。
正式产品仍需前端登录/改密/会话失效处理与 HTTPS。

## 验证命令

```powershell
python scripts/workspace.py check
python scripts/workspace.py test
# 自行安装 Nmap/Gatus 后，显式启用真实本机和回环工具测试：
python scripts/workspace.py test --local-tools
```

默认真实工具项会明确跳过，不能把跳过当成已通过。
新增测试会把源码/构建移入带中文、空格的临时目录，真实启动 HTTP，验证登录、台账、生产 JS 和注销；
临时用户只进入临时库，不污染开发库。`--wheelhouse` 只解决 Python 包的离线安装，不代表 npm/整套安装离线。

## 目录和交接

| 位置 | 用途 |
|---|---|
| `scripts/workspace.py` | 安装、检查、开发库、账号、启动与测试 |
| `scripts/data_seed.py` / `scripts/verify_seed_http.py` | 私有历史快照、脱敏种子、安全导入与临时副本真实 HTTP 验证 |
| `tests/` | 新启动安全和真实 HTTP 验证 |
| `.github/workflows/verify.yml` | Windows 干净环境自动验证 |
| `docs/协作就绪审计-2026-11-16.md` | 详细缺口、处理、证据和未测项 |
| `docs/工具与运行环境.md` | 七类工具的位置和安装/分发边界 |
| `CONTRIBUTING.md` / `SECURITY.md` | 协作流程、安全与数据边界 |
| `net-assistant/backend/` | 0.10.0 后端源码、迁移、契约、测试 |
| `net-assistant/frontend/` | 前端源码；类型生成入口已对齐 0.10.0 |
| `.runtime/` | 每位协作者自己的环境、构建和数据，不入库 |

现有旧 API/服务不由新入口接管，旧工作库早期 0006 的六处主键声明差异仍需独立修复。
`serve`/`check` 只读检查版本和这六处结构，拒绝不匹配，不自动迁移。
不要在运行服务共用的源码目录新增迁移；后续开发建议独立 clone。

本次提交只整理 `project` 源码；不含外层原件、工具箱、真实库、私钥和系统程序目录。
原工作目录的 Git 历史保持不变；新私人协作仓库从经核对的干净源码快照开始，不继承旧历史。
历史说明中的个人路径和内网地址会脱敏；程序源码逐字节保留。
**仓库保持私有，公开前必须重新审查。**
未替团队擅自选择开源许可证。进一步说明见上述文档和后端 `docs/前端对接说明.md`。
