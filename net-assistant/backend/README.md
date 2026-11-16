# 网维助手 · 巡检后端

这是实际巡检程序的独立工程，不是项目说明网站的 Node 共享进度服务。

> **当前协作基线 0.10.0，2026-11-16。** 平台登录和受控 SSH 以 `app/main.py`、
> `docs/openapi-0.10.0.json` 及 `docs/前端对接说明.md` 为准。
> 新机器先看仓库根 `README.md` 的隔离启动流程，不直接使用下文历史工作库/路径。
> 下方版本保留为历史；源码更新不代表旧运行服务已经升级。

## 0.9.0：锐捷交换机自动接入

- 一次配置授权范围与 SNMPv3 authPriv 凭据后，由后台自动探测、识别、读取、入库和周期重试；前端只读轮询，无需逐台手点连接。
- 默认 `configs/switches.local.json` 沿用原实验网授权，`profiles=[]`，因此等待配置且不发送交换机探测。不能把此实验网直接当作未来实体交换机的现场管理网。
- 参考 `configs/switches.example.json` 配置。`targets=[]` 表示授权范围内自动发现；指定地址仍须属于该范围且不在排除项中。凭据通过 `auth_key_env`／`priv_key_env` 引用服务端环境变量，不在 JSON、接口或日志中保存密码。必须由实际运行 `NetAssistant-Monitoring` 的服务进程获得这些变量；普通终端的变量不自动传给 SCM 服务。新增服务环境凭据后需重启该项目服务；采集范围和配置文件可自动重读。
- 仅支持 SNMPv3 authPriv，认证可显式选 SHA／SHA256／SHA512，加密 AES128。不猜凭据、不自动降级 SNMPv2c、不执行 SET。
- 实际采集：系统名称、描述、sysObjectID、运行时间；标准接口状态、接口速率及 Counter64 累计字节；标准 MAC 转发表、FDB→VLAN 映射、桥端口→ifIndex 映射、LLDP 邻居。空表不武断判定“不支持”，以分项状态和原因展示。
- LLDP 本地端口号不冒充 ifIndex；FDB ID 不冒充 VLAN ID；Counter64 以字符串传输避免前端精度损失。当前不读取厂商私有 CPU／温度／PoE，不假设接口数就是物理端口数。
- 成功登记的是“管理端点”，不是认证后的物理资产身份；不按 IP 强行关联原资产。失败保留独立记录，最新查询不以旧成功结果兜底。
- `NetAssistant-Monitoring` 同时托管独立交换机线程，未配置或采集失败不阻塞原 Gatus／本机快照。采集周期从上轮结束后计算，前端每15秒只读更新。
- 可独立运行 `python -m app.switches.worker validate|status|run --config configs/switches.local.json`；`validate` 不发网络请求。新增依赖见 `requirements-switches.txt`，仅装入本项目虚拟环境。
- 查询入口（全部以 `/api/v1` 为前缀）：`/switches/status`、`/switches`、`/switches/{id}`、`/switches/{id}/snapshots/latest`、`/switches/{id}/snapshots`、`/switch-snapshots/{id}`、`/switch-collection-runs`。全部 GET，不提供无认证的任意目标操作入口。
- 软件协议测试使用隔离回环 SNMPv3 代理和临时数据库，不能替代锐捷实机兼容验收。实机型号、现场管理范围、只读账户与配置仍待提供；不宣称任意交换机插线即可读数。

**先了解程序做了什么、收集了什么：**
[后端程序功能与采集数据说明](<checkout-or-user-tool-path>
代码实现与自动验证由助手负责，人工操作与真实功能验收由用户完成，见
[人工操作与功能验收清单](<checkout-or-user-tool-path>

## 0.8.0：完整本机快照与集成自动化（2026-11-16）

**当前进度、实施记录和待办统一保存在后端 `plan.md`。下面旧版本小节是历史记录，不能覆盖本节现状。**

| 文件／入口 | 功能 | 实际保存或返回的信息 |
|---|---|---|
| `app/collectors/windows.py` | 使用现成 Windows 只读命令采集本机 | 网卡、接口编号／状态、MAC、多个 IPv4／IPv6 地址与作用域、邻居缓存 |
| `app/collectors/store.py`、`models.py` | 稳定采集设备编号、完整快照及失败／中断记录 | 完整 JSON、来源、原观测时间、开始／结束时间、可选显式资产关联；不会把邻居缓存当在线证明 |
| `migrations/versions/0004_network_snapshots.py` | 增加 `network_devices` 和 `network_collection_runs` | 迁移前自动一致性备份；保留既有扫描任务和资产记录 |
| `app/collectors/api.py` | 最新／历史／单条快照只读查询 | 只读数据库；GET 不启动采集或迁移；最新采集失败时不拿旧成功替代 |
| `app/collectors/cli.py` | 显式单次采集并持久化 | 必须提供绝对数据库路径、稳定设备 UUID、配置标签；可提供已存在的资产 UUID |
| `app/monitoring/automation.py` | 同一托管服务统一运行 Gatus 与周期本机采集 | 本地配置绑定心跳、采集结果、Gatus 就绪／故障状态；独占运行、不隐式扩展目标 |
| `scripts/manage-monitoring-service.ps1` | 预览、安装、查询、启停、移除项目专属监控服务 | 低权限虚拟服务账号、Automatic 启动、故障自动恢复；停止与移除不删除数据 |
| `configs/monitoring.local.json` | 已授权虚拟机试运行计划 | 仅 `192.0.2.80:135/445` TCP，每60秒检查；TCP成功不是完整业务健康证明 |
| `configs/automation.local.json` | 本机采集与监控统一配置 | 本机快照完成后间隔300秒再次采集；Gatus使用独立SQLite，不混入巡检库 |

新增只读接口：

```text
GET /api/v1/network-devices
GET /api/v1/network-devices/{device_id}/snapshots/latest
GET /api/v1/network-devices/{device_id}/snapshots?limit=50&cursor=...
GET /api/v1/network-snapshots/{run_id}
```

`snapshot` 保留采集契约字段（例如 `interface_index`、`prefix_length`），外层查询信封使用 camelCase。
本机设备编号为配置中稳定保存的 UUID，不通过地址／MAC／名称猜测资产身份；
`device_label` 是配置标签，不是采集到的设备名。当前未关联台账资产时 `assetId=null`，
不会为方便关联创建虚假发现记录。显式资产关联必须指向已存在资产，历史快照不随新配置回写。
这不是远程主机完整网卡盘点，也没有新增SNMP采集。

服务管理入口：

```powershell
.\scripts\manage-monitoring-service.ps1 -Action Status
.\scripts\manage-monitoring-service.ps1 -Action Preview
.\scripts\manage-monitoring-service.ps1 -Action Stop
.\scripts\manage-monitoring-service.ps1 -Action Start
```

只有显式 `Install` 才安装服务；`Remove` 要求先停止，保留配置、数据库、日志及备份。
查询API仍是独立进程，不由监控服务托管；默认工作库的应用会读取项目 `monitoring.local.json`，
其他数据库必须显式指定监控配置，避免测试或其他项目被接到工作监控。
两个正式项目服务目前均已启用：每日扫描仍按09:00与每日去重规则执行，监控服务持续托管Gatus和本机采集。
已实际验证停止／重启、历史留存、监控服务崩溃后的SCM恢复；未为验证而重启整台电脑或注销用户。
完整本机快照含缓存数据，记录数量不是在线设备数；历史目前保留，不擅自自动删除。

本轮最终复验：`RUN_LOCAL_TOOLS=1` 的完整后端套件 **224项通过、0失败，159.24秒**
（含6项真实工具测试）；依赖检查、Python编译、管理脚本语法及工作配置校验通过。
最终工作配置另实测300秒定时采集并经实际HTTP读回；工作库、迁移前备份与Gatus库完整性均为ok。
服务级验证不混入pytest测试数，也不等同于用户已经验收。

## 0.7.1：扫描入口切换与重复实现归档（2026-11-16，历史记录）

| 项目 | 当前实际状态 |
|---|---|
| 扫描引擎 | 手动和每日扫描共用 `app/discovery/execution.py`，只调用 Nmap；默认 `engine=nmap`，明确写 `native` 的新配置会拒绝，不做隐式回退 |
| 本机扫描配置 | `configs/vmnet8.local.json` 已明确指定现有 Nmap 绝对路径；目标、排除项、115个端口和源地址保持原范围 |
| 名称发现 | 该配置已开启 mDNS，接口仅 `192.0.2.193`；发现结果只关联既有目标，不扩展网段；其他示例不默认在所有网卡发多播 |
| OS 指纹 | 该配置已开启；实际请求不能保证有候选，新增 `osDetection` 与原因，区分未请求、候选、条件不足、未匹配；不当作确认系统 |
| 重复实现 | 旧 TCP/ICMP/横幅探测移至 `legacy_native/probes.py`，旧调度移至 `legacy_native/runner.py`；保留历史回归测试，正式入口不导入归档包 |
| 继续使用的自有代码 | 授权、预算、名称补充、MAC解析、HTTP/TLS/截图取证、证据归一、数据库、资产关联和API，不属于可被扫描器整段替换的重复协议引擎 |
| 配置备份 | 原配置按字节保存在 `legacy_native/configs/vmnet8.pre-nmap-20261116.json`，该目录被Git忽略；其中相对端口配置路径以原 `configs` 目录为基准，备份不是另一份可直接运行的新计划 |
| 后台状态 | 切换时现有 `NetAssistant-Discovery` 服务为停止状态，未擅自启动；配置已切换不等于后台此刻正在扫描 |
| Gatus | 已有可执行程序、运行入口、独立SQLite与助手只读API；没有正式目标或常驻服务，所以不是已经在后台持续监控 |

### 集成与数据库边界

| 数据来源 | 调用链 | 保存与传输 |
|---|---|---|
| Nmap | 手动CLI／每日调度 → `execute_scan` → Nmap适配器 | 范围、任务、主机、端口、服务、名称、MAC、厂商线索、OS候选／检测状态写入巡检SQLite；查询API从库读取 |
| mDNS | 扫描任务内调用 python-zeroconf | 名称来源与服务实例信息写入同次任务的证据，随主机API返回；不冒充认证身份 |
| 网站取证 | Nmap发现开放端口后调用取证 | 标题、响应码、选定响应头和截图引用走现有巡检库／文件链路 |
| Gatus | 管理CLI托管进程；助手监控API读取Gatus | 健康历史在独立Gatus SQLite，不重复塞进巡检库；助手返回状态及最近历史 |
| Windows本机网卡／邻居 | 当前仍为独立只读CLI；mDNS用它核验本机接口 | 完整快照尚未自动持久化至资产台账，也没有完整网卡快照API |
| 交换机SNMP | 只有结果契约，尚无真实采集器接入 | 没有SNMP采集、入库或传输完成的证据，不能把结构定义当成已采集 |

SNMP 组件已核对 **PySNMP 7.1.32** 的项目元数据，来源为
`https://pypi.org/pypi/pysnmp/7.1.32/json`；项目仓库为
`https://github.com/lextudio/pysnmp`。它是现成协议组件，不等于已经完成锐捷设备采集。
本轮没有安装它、填写SNMP凭据或向未知交换机发请求；具体型号、支持的MIB和只读授权仍待实际设备确认。

### 实际验证说明

- 保留原测试，并新增默认入口／拒绝旧引擎／无回退、OS未识别原因等测试。
- 真实工具测试改用临时启动的本机HTTP API接收数据，不再仅用进程内ASGI传输：
  实际验证 Nmap IPv4/IPv6 → 临时巡检库 → HTTP JSON；
  实际验证 mDNS → 扫描证据 → 库 → HTTP JSON；
  实际验证 Gatus → 独立SQLite → 助手 → HTTP JSON。
- 补做管理员/Npcap环境下的真实 OS 回环尝试：本机基准为 Windows 11，
  此次Nmap未给出OS候选，端口条件不足，记录 `limited / open_and_closed_tcp_not_observed`，
  不宣称OS准确性通过。没有读取虚拟机配置补充目标系统。
- 原授权实验网仅选此前观察的两个地址做隔离验证，不扩大扫描范围、不写工作库。
  首次使用30秒单目标时限的验证为部分完成、一个目标未成功；按正式60秒参数复验后，
  两目标均完成，共230项配置TCP端口观测，零采集错误，并由实际HTTP API返回保存的数据。
  不将首次失败隐藏成全程一次通过，也不把上述两地址抽验称为整个网段已扫完。
- 本轮未启停已有服务、未修改工作数据库、驱动、防火墙或交换机；临时HTTP服务和Gatus测试进程退出后关闭。
- 最终完整复验：**205项通过，0失败，120.54秒**（含5项真实回环工具测试及归档实现的历史回归）；
  `pip check`、`compileall app legacy_native`、Gatus空计划校验通过。
  正式扫描配置和服务引导入口校验通过，主入口导入时未加载 `legacy_native`。

## 0.7.0：成熟本地工具接入（2026-11-15，历史记录）

**源码已接入，实际扫描计划尚未切换。** 不改真实工作库、现有每日服务、真实目标配置或前端。
本轮执行顺序：范围／契约测试 → 工具适配 → 隔离入库与 API → 真实回环验证 → 完整回归。

| 部分 | 已实现 | 启用与限制 |
|---|---|---|
| Nmap | 独立进程调用、受控参数、XML 解析、TCP 覆盖、服务版本、名称候选、网卡厂商线索、系统候选 | 本机复用独立安装的 7.92，不打包 Nmap/Npcap；新配置设 `engine=nmap`，已有配置默认仍为 `native`，不会静默换引擎 |
| IPv6 | 明确地址／`/128` 候选、接口作用域、入库、查询和历史导出 | 不枚举 `/64`；链路本地地址需数字接口编号，例如 `fe80::12%7`；真实回环 `::1` 已验证，实网链路本地与指定源接口未验 |
| 名称 | 保留系统解析、NetBIOS；接收 Nmap 与 python-zeroconf 的多个名称候选 | mDNS 默认关闭，需明确授权本机接口与服务类型；服务实例名与主机名分开保存 |
| 本机网络 | Windows 原生网卡、MAC、IPv4/IPv6 多地址、接口编号、邻居缓存及状态 | `python -m app.collectors.windows` 只读输出，不写工作库；缓存不是当前在线证明 |
| 交换机准备 | `app/collectors/contracts.py` 定义接口、邻居、FDB/VLAN、LLDP 结果契约 | 尚无实际 SNMP 采集器，未连接或宣称兼容任何交换机 |
| Gatus | 固定 v5.38.0 本机程序、受控配置生成、独立 SQLite、HTTP/HTTPS/TCP 条件、状态和最近100条历史、显式资产编号关联 | 不自动把扫描对象加入监控；当前没有正式监控目标或常驻服务 |

### 工具与数据边界

- Nmap 默认 `-sT -Pn -sV --version-light`，不执行 NSE、漏洞脚本、登录或密码测试。
  `-Pn` 的“强制主机 up”不当成在线证明；`filtered` 不当成关闭，分组端口覆盖不完整时报错。
  `nmap_os_detection=true` 才请求操作系统指纹，需另行核对权限／已有驱动，**本轮未做真实 OS 指纹验收**。
- `nameCandidates` 保留名称来源与冲突；`vendorHint` 是网卡前缀厂商线索，不是整机品牌确认，
  本地管理／随机化 MAC 不强套厂商。`osCandidates.accuracy` 是工具原始系统指纹分，不是品牌概率。
  按端口表猜测的服务为 `port_table_hint`，不填成已观测产品／版本；人工名称和分类不被覆盖。
- 多网卡／多地址已经有本机结果结构；远程资产继续使用已有人工确认关联，
  **尚未实现把远程网卡清单自动持久化为完整台账**，不凭相同 IP、主机名或 mDNS 强行合并。
- Gatus API 仅允许显式回环上游。配置禁止 URL 凭据、查询串及环境模板，
  默认不跟随跳转、不跳过证书校验；监控外网／域名还需精确 `allowed_hosts` 和 `allow_public=true`。
  没配置、无样本、上游对象缺失、数据过期、上游故障分别表达，不以空成功替代失败。
- Gatus 数据库与巡检库分开，拒绝复用已有无关数据库；生成配置不覆盖已有文件。
  结果时间采用 Gatus 原始观测时间，读取 API 的时间不是检查发生时间。
  上游对象键包含目标与检查条件指纹；修改计划后必须重新启动 Gatus，
  旧配置的成功样本不会被移作新目标／新条件的健康证明。
- 不提供通用 UDP 扫描配置、通知渠道／凭据配置、远程认证主机盘点和监控前端。
  后续拓扑页面仍须支持人工命名、选择设备类型，人工结果优先于自动建议。

### 已安装与验证环境

- Gatus：`tools/gatus/bin/gatus.exe`，v5.38.0，编译工具链 go1.26.11 位于项目缓存。
  系统 Go 1.26.1 未替换；本机 Nmap/Npcap 未升级，未修改防火墙或服务。
- 可选名称依赖已装入后端 `.venv`：`requirements-collectors.txt`，
  `zeroconf==0.154.0`、`ifaddr==0.2.0`。`pip check` 无依赖冲突。
- Gatus 编译缓存保留于 `tools/gatus/cache`，与二进制／运行数据一起被 Git 忽略；
  缓存只为重编译所需，不是业务数据，本轮未擅自清理。
- 本机只读查询实测取得多网卡和 IPv4/IPv6 地址，未读取虚拟机配置文件或给目标补造身份。
- `tests/test_local_tool_integration.py` 实际运行 Nmap IPv4/IPv6 回环扫描，
  实际发布并发现仅在回环接口上的 mDNS 服务，以及 Gatus HTTP/TCP 检查、
  503 故障／恢复、拒绝跳转、自签名证书失败和 SQLite 重启历史验证。
  所有测试记录在临时目录，测试进程结束即关闭，不写工作库，不留测试服务常驻。
- 最终复验：启用真实回环工具测试后的完整后端套件 **199 项通过**（含4项真实工具测试），
  `pip check`、Python 编译检查、Gatus 管理脚本校验均通过。
- 真实交换机、实网扫描识别率、OS 指纹准确性、正式通知和开机自启未验收；
  用户最终验收尚未完成。

### 配置和使用入口

在当前后端根目录执行。示例文件不是实网扫描或持续监控授权：

```powershell
# 只校验回环 Nmap 示例，不发扫描请求
.\.venv\Scripts\python.exe -m app.discovery.cli validate --config configs/nmap-loopback.example.json

# 空监控示例可校验；没有明确目标时 render/run 会拒绝启动
.\scripts\manage-gatus.ps1 -Action Validate -Plan configs/monitoring.example.json

# 正式目标确认后，使用独立的 monitoring.local.json；
# Run 在当前会话托管 Gatus，Ctrl+C 只停止自己启动的进程，不安装服务/自启
.\scripts\manage-gatus.ps1 -Action Run -Plan configs/monitoring.local.json
.\scripts\manage-gatus.ps1 -Action Status -Plan configs/monitoring.local.json
```

计划对象示意（不是已经启用的监控记录）：

```json
{
  "api_url": "http://127.0.0.1:18080",
  "allowed_hosts": ["需要监测的实际主机"],
  "allow_public": false,
  "allow_loopback": false,
  "endpoints": [{
    "id": "stable-service-id",
    "url": "http://需要监测的实际主机:8080/health",
    "asset_id": null,
    "interval_seconds": 60,
    "timeout_seconds": 5,
    "status_code": 200,
    "response_time_ms": 2000
  }]
}
```

`id` 为稳定小写字母／数字／连字符标识；`asset_id` 仅接受显式 UUID，
来源显示为 `operator_config`，不当成已认证设备身份。HTTPS 可加 `certificate_days`，
TCP 使用 `tcp://主机:端口`，不把 TCP 可连通冒充应用业务健康。
本地 Go 构建可用 `scripts/manage-gatus.ps1 -Action Build` 重现；已有二进制时拒绝覆盖。

启动网维助手 API 时，显式将 `INSPECT_MONITORING_CONFIG` 设置为监控计划的绝对路径。
新增 `GET /api/v1/monitoring` 与 `GET /api/v1/monitoring/{endpoint_id}`，
只查询，不启动检查、不安装工具、不迁移数据库。未配置环境变量时返回 `not_configured`。
当前动态 `/openapi.json` 含新接口，旧 `docs/openapi-0.6.0.json` 保留为历史契约，不回写。

自动回归与真实工具复验：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
$env:RUN_LOCAL_TOOLS='1'
.\.venv\Scripts\python.exe -m pytest -q -s tests/test_local_tool_integration.py
Remove-Item Env:RUN_LOCAL_TOOLS
```

## 0.6.0 已有扫描增强

以下为此前实现并继续保留的扫描能力：

- 对所有授权地址检查配置 TCP 端口，不再用 Ping、ARP 或少数发现端口筛掉后续检查。
  优先处理已发现地址；预算耗尽为部分完成，已取得的名称、端口和服务证据保留。
- 系统反向名称解析失败后，可向目标单播查询 UDP 137 NBSTAT（`netbios_enabled` 可关闭）；
  名称有来源，不是身份认证。MAC 仍受同链路 ARP 条件限制。
- 发现快照和只读 API 新增 `hostname`、`hostnameSource`、`portScan`、`services`、`websites`。
  协议证据与端口提示分开；未知服务不冒充已确认部署。人工台账名称不被覆盖。
- Web 取证改为有限 GET，只保存标题和筛选后的响应头，不保存正文、Cookie，不跟随跳转。
  网站检查仍依据 `http_ports` / `https_ports`，不能靠 IP 自动枚举全部域名虚拟主机。
- 现有页面支持截图预览和打开原站，不使用 iframe，也不执行定期监测。

### 可选截图与全 TCP 模式

**不会自动修改真实扫描配置或安装运行依赖。** 启用截图时，在扫描工作进程的 Python 环境安装：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-screenshots.txt
```

Windows 使用已安装的 Microsoft Edge，新建无用户登录状态的浏览器上下文。
Linux 需另行准备 Playwright Chromium；本轮未验证 Linux。
在实际扫描配置 JSON 添加 `"screenshots_enabled": true` 才会采集。
未安装依赖、浏览器不可用、截图失败分别保留原因；旧扫描不会补图冒充历史截图。
截图仅为禁用脚本的 1280×800 静态首屏；只允许当前 IP/端口/协议的资源，
限制请求数和字节，不登录、不点击、不跟随跳转。脚本型网站可能无法完整显示。
请求要求无压缩响应；目标仍返回压缩内容时跳过正文/截图并保留原因，避免无界解压。
截图保存于数据库旁 `artifacts/screenshots`，通过所选任务的只读截图接口读取，
不公开挂载整个数据目录。截图可能包含页面内容，应与巡检库一并限制访问。

默认 `"tcp_port_mode": "configured"`，显式设为 `"all"` 才检查 TCP 1–65535。
两种模式都只扫描授权地址；全端口可能明显增加耗时，需要自行核对总预算。
`hostname_enabled`、`netbios_enabled`、`passive_service_detection` 默认开启；
`screenshots_enabled` 默认关闭。`validate` 会显示有效端口数量与截图开关，不发包。
旧任务只读兼容，不回填名称、服务或图片。API 模型见 `docs/openapi-0.6.0.json`。

以下为原有后台运行与台账能力：
在可配置发现、证据、SQLite与稳定台账上，
保留扫描后自动建档/保守关联、每日去重和手动扫描；每日托管已改为不依赖个人登录的 Windows 服务，
新增独立工作进程心跳与只读调度状态/历史接口。
自动登记不是授权采集；尚非完整故障巡检或主机采集系统。
最新操作入口见 `docs/后台服务与调度状态-使用说明.md`；
功能与 AI 安装/测试动作的区别见 `docs/项目实际能力与操作边界.md`。
0.4.0 自动身份规则仍有效，但其 Interactive 计划任务现为回退方式。

## 上一轮真实扫描结果（2026-11-14，历史观测，不是当前在线状态）

任务 `00000000-0000-4000-8000-000000000001`：

- 实验范围 `192.0.2.192/24`，排除宿主 `.1`、NAT `.2`、基础设施 `.254`。
- 完成 251 个候选地址的发现，2 台有直接响应。
- 每台完成配置的 115 个常用 TCP 端口，共 230 项；原始探测记录 1230 条。
- `.141`：135、139、445 可连接，112 项超时。
- `.147`：115 项超时。不是“所有端口关闭”，也不是“没有服务”。
- 本次未命中服务取证配置端口，没有取得虚拟机 HTTP、TLS、横幅证据。
- VMware 名称与系统提示来自本机 `.vmx` 配置按 MAC 关联，不是网络操作系统指纹。
- CPU、内存、进程均未采集；不填零冒充结果。

完整端口、证据来源和限制见 `reports/00000000-0000-4000-8000-000000000001/report.md`。同目录含 `observations.json`；默认忽略实验配置、数据库与报告，不提交私有地址和机器路径。

## 资产分类与权限

来源、纳管状态、业务类型、采集授权分别表达：

- 本轮发现记录默认为 `network_discovery / discovered / unknown / not_enrolled`。
- `hostMetrics: null`，`hostMetricsStatus: not_collected`。
- 允许网络探测不等于允许登录、读进程或安装 Agent。
- `discovery_hosts` 仍是**每次发现快照**，保留原始分类；不因登记台账回写历史。
- 已有独立 `assets` 台账与关联；自动档案为 discovered，人工登记为 managed，
  都不是所有权证明或授权采集。已有两台人工档案负责人仍为 null，不改写为自动成果。
- 发现查询新增 `assetId` 和 `associationStatus`，当前台账信息另从资产接口读取。
- 纳管、改名、关联、撤回关联通过本机 CLI；尚无网页操作按钮、授权授予/撤销、
  Agent、主机指标上传或授权管理接口。

“发现资产未授权采集”和“人工纳管但未授权采集”分开表达。
使用规则见 `docs/稳定资产台账-使用与接口.md`，后续采集约束见 `docs/资产分类与授权边界.md`。

## 运行环境与安装

本机实测 Python 3.13.7 / 64 位，使用本目录 `.venv`。`.in` 为依赖范围，`.txt` 为本轮实测精确版本（包括传递依赖）。锁文件针对 Windows / Python 3.13；没有验证其他平台或全新环境重装。

新环境先创建虚拟环境，不要覆盖正在使用的环境：

```text
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

## 启动只读 API

PowerShell 进入工程：

```powershell
Set-Location -LiteralPath "<checkout-or-user-tool-path>"
```

CMD 用 `cd /d "<checkout-or-user-tool-path>"`。随后两种终端均可执行：

```text
.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers
```

浏览器访问 `http://127.0.0.1:8000/docs`，按 Ctrl+C 停止。默认数据库固定在工程根 `data/inspection.sqlite`，可用 `INSPECT_DB` 指定绝对路径。数据库缺失时查询返回 503，不会由只读 API 偷偷创建空库。

| 接口 | 含义 |
|---|---|
| `GET /health/live` | 应用存活，不代表数据库、调度或目标健康 |
| `GET /health/ready` | 尚未实现，404 |
| `GET /api/v1/discovery-jobs` | 发现任务列表 |
| `GET /api/v1/discovery-jobs/{job_id}` | 任务、配置快照和覆盖量 |
| `GET /api/v1/discovery-jobs/{job_id}/hosts` | 本任务发现快照及分类、开放端口 |
| `GET /api/v1/discovery-jobs/{job_id}/probes` | 每次探测证据，可按 address/method/status 筛选 |
| `GET /api/v1/assets`、`GET /api/v1/assets/{asset_id}` | 稳定台账列表、详情 |
| `GET /api/v1/assets/{asset_id}/observations` | 已确认关联的发现及历史地址，含观测和确认时间 |
| `GET /api/v1/assets/{asset_id}/audit` | 登记、关联、撤回和修改审计 |
| `GET /api/v1/discovery-hosts/{host_id}/asset-association` | 当前关联与待确认线索，不自动写入 |
| `GET /api/v1/scheduler` | 每日计划、心跳、数据库读取状态、最近自动结果、能力边界 |
| `GET /api/v1/scheduler/runs` | 本计划自动扫描历史，只读分页，不含手动任务 |
| `GET /openapi.json` | 当前模型；静态副本见 docs/openapi-0.6.0.json，保留旧版 |

分页默认 50、最多 200，返回 `nextCursor`。GET 不触发检测。本轮没有启动扫描的 POST。文档 UI 不是业务前端，其静态资源默认依赖 CDN。错误包提供 code/message/requestId/fieldErrors；错误响应的 OpenAPI 细化仍待后续补充。

仅监听本机；不改成 `0.0.0.0`、不开防火墙端口、不接宝塔代理。鉴权与完整部署边界尚未完成，不应开放实验网或公网。
API没有常驻/自启；每日扫描由独立 Windows 服务托管，不依赖 API 常驻。
默认工作库对应本工程每日计划；独立库使用 `INSPECT_SCHEDULE_CONFIG` 明确指定绝对路径，不能混读另一库的计划。

## 配置与执行扫描

`configs/scope.example.json` 是可编辑示例，**不是扫描授权**。`configs/common-tcp-v1.json` 是 115 个常用 TCP 端口清单，不是全端口或 UDP 覆盖。`vmnet8.local.json` 是本次授权实验配置，算法不内置该网段。

支持配置：IPv4 单地址/CIDR/起止范围、排除、源地址、端口及取证子集、并发、超时、总预算、地址上限。只填写自己有权测试的目标。

```text
.\.venv\Scripts\python.exe -m app.discovery.cli validate --config configs/vmnet8.local.json
.\.venv\Scripts\python.exe -m app.discovery.cli scan --config configs/vmnet8.local.json
```

`validate` 只读本机接口/配置，不发目标探测、不创建数据库；`scan` 才发包并保存。不要为了查看结果再次扫描。重导出已有任务：

```text
.\.venv\Scripts\python.exe -m app.discovery.cli export --job-id 00000000-0000-4000-8000-000000000001
```

执行扫描前必须重新核对授权与范围。换实验环境只改配置；本轮只验证当前范围。

## 怎样搜集、保存与解释

1. 校验配置和实际源网卡，保存范围版本与任务快照。
2. Windows 原生 ICMP、同链路 SendARP、配置 TCP 补充探测综合发现。ARP 可能使用缓存，仅为地址解析候选，不能单独判在线。
3. 优先处理已有候选，再对其余授权地址执行有效 TCP 端口集，不以禁 ping 或发现端口无响应跳过。
4. 对开放端口进行配置的 HTTP 有限 GET、严格校验 TLS，以及受限的被动横幅识别。
   只在内存读取有限 HTML 提取标题，不保存正文，不跟随重定向、不保存 Cookie/认证头、
   不登录、不做漏洞或口令测试。不向原始打印端口 9100 自动发送 HTTP。
5. 保存方法、时间、状态、耗时、原因和有界证据，再由只读 API 提供给未来页面。

超时不等于关闭；端口开放不等于服务/版本识别；未发现不等于不存在。`completed` 表示本任务计划检查已执行完，不代表所有资产被发现或全部健康。

原生 ARP 的系统等待不保证等于 `timeout_ms`；预算取消不能强制中断已进入原生调用的线程，清理和退出可能延后。ICMP 指定源地址时显式绑定源地址。

独立 SQLite 使用 SQLAlchemy 2 与 Alembic；有外键、短事务、单扫描写入者文件锁、回滚日志、只读连接、任务中断恢复。迁移拒绝无关表，不碰共享进度数据库。四类业务表保存范围、任务、发现快照、探测证据；另有迁移版本表。JSON 导出不是完整备份。每日备份/轮换、保留清理尚未实现。

资产模块新增 `assets`、`asset_discovery_links`、`asset_audit_events` 三张表。
旧库升级前自动生成并检查 `data/backups/*.sqlite` 一致性备份；已用临时库验证备份恢复读取。
迁移显式事务支持失败回滚；CLI 扫描和台账写入共用文件锁，台账内部用事务与 revision 防并发覆盖。
不要直接改表模拟采集授权，不要把资产 UUID 或 MAC 当作认证凭据。

## 查看和维护台账（不发网络探测）

```text
.\.venv\Scripts\python.exe -m app.assets.cli list
.\.venv\Scripts\python.exe -m app.assets.cli show --asset-id 00000000-0000-4000-8000-000000000001
.\.venv\Scripts\python.exe -m app.assets.cli observations --asset-id 00000000-0000-4000-8000-000000000001
.\.venv\Scripts\python.exe -m app.assets.cli audit --asset-id 00000000-0000-4000-8000-000000000001
```

初始两台台账已人工登记，不要重复register。0.4.0起，后续扫描自动建档/关联；
同scope有效MAC历史唯一且本次不重复时沿用UUID，无MAC/歧义则新建待核验档案，不凭IP合并。
全部写操作与错误码示例见 `docs/稳定资产台账-使用与接口.md`。
更换网络环境时核对逻辑范围，不能把同一个范围名称当作自动识别的物理网络身份。

## 测试与边界

```text
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/smoke_test.py --job-id 00000000-0000-4000-8000-000000000001
.\.venv\Scripts\python.exe scripts/smoke_test.py --asset-id 00000000-0000-4000-8000-000000000001
```

测试使用独立临时库与回环服务，不修改真实任务和团队进度。冒烟启动本机临时 Uvicorn，
读取真实记录后关闭自己的进程。任务01/02历史保留；本轮见 `docs/任务03-资产台账验收.md`。

## 每日自动扫描与手动入口

计划文件 `configs/daily-scan.local.json` 默认北京时间09:00；
`NetAssistant-Discovery` Windows 服务已安装并运行，原登录任务停用保留。
无需个人用户登录，但需管理机开机、实验网络可达。只补当天到期，不补过去每日积压。
改配置后 Stop / Start 服务使新实例生效；只想长期停扫可将计划 enabled=false 后重启服务，不删除资产库。

```powershell
.\scripts\manage-discovery-service.ps1 -Action Status
.\.venv\Scripts\python.exe -m app.scheduling.cli status --config configs/daily-scan.local.json
# 以下需要管理员 PowerShell；本机已安装，不必重复 Install
.\scripts\manage-discovery-service.ps1 -Action Stop
.\scripts\manage-discovery-service.ps1 -Action Start
```

手动仍使用前文 `app.discovery.cli scan`，不占每日自动名额。
自动与手动共用扫描锁；partial/failed计入当天尝试，busy不占名额。
每日任务结果、退出码、日志和身份局限详见最新使用说明。
工作进程每30秒判断到期、约2秒更新心跳，不是每30秒重扫网络。
新状态API不等于完整健康就绪；心跳正常也可能最近扫描失败。

**未完成**：业务写操作前端、可信采集端身份与授权工作流、Agent、CPU/内存/进程、逐设备高频巡检调度、
防抖事件、故障处理备注/恢复、账号、远程访问、每日自动备份与完整巡检就绪检查。

任务05/06到后台服务与只读运行状态为止。已有服务账户真实单目标扫描/自动建档/重启去重证据，
但未真实重启电脑、注销用户或迁移新机器，也未用启动测试冒充正式09:00自然触发。
后续可用最小只读页面展示真实台账/观测，或单独评审采集接入契约；
不自动继续安装 Agent，不宣称 UUID 台账解决了网络设备身份认证。

## 任务07：简单只读工作台

已新增独立 React / TypeScript 前端，消费现有资产、发现和调度 API。
生产构建在 `<checkout-or-user-tool-path>`，
API 启动时仅挂载该目录到 `/console/`，根路径跳转到该页。
缺构建时 `/console/` 返回503说明，不影响 `/health/live`；API未知路径仍404，不被页面兜底。

启动API后打开 `http://127.0.0.1:8000/console/`。本轮无需同时启动 Node 开发服务。
页面刷新只GET，不启动扫描，不修改真实资产、不做数据库迁移，也不接项目说明站的共享勾选库。
CPU、内存和进程明确显示未采集；首批人工登记与后续自动关联分别展示。

API仍不是本轮新安装的后台自启服务；已存在的Windows发现服务与本机API进程独立。
开发、构建、验证和部署边界见
`<checkout-or-user-tool-path>`。
