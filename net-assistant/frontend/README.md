# 网维助手 React 工作台

工作台通过相对路径 `/api/v1/…` 读取后端保存的资产、扫描批次、探测证据、每日调度和交换机采集结果。API 契约和登录、权限、分页规则见[前端对接说明](../backend/docs/前端对接说明.md)。

## 本机打开

按[仓库 README](../../README.md) 准备运行环境、创建用户并运行 `start.cmd`。在 `http://127.0.0.1:8001/docs` 中执行 `POST /api/v1/auth/login`，然后在同一浏览器打开 `http://127.0.0.1:8001/console/`。

## 开发和构建

在仓库根目录启动后端。另开 PowerShell 窗口，在仓库根目录进入前端源码目录。下列命令使用已准备好的项目内 Node.js 与 npm。

```powershell
$env:Path = "$PWD\.runtime\tools\node;$env:Path"
Push-Location .\net-assistant\frontend
npm.cmd ci
npm.cmd run dev
```

浏览器打开 `http://127.0.0.1:5182/console/`。开发服务器将 `/api`、`/health` 和 `/openapi.json` 转发到本机 8001 端口，保留浏览器请求的 Host 与 Origin。自定义后端端口时，同步修改 [vite.config.ts](vite.config.ts) 中的 `backend.target`。使用项目内运行环境提供静态页面时，在仓库根目录重新运行 `bootstrap.ps1 setup` 即可同步源码并构建。

修改前端后，在前端源码目录执行：

```powershell
npm.cmd test
npm.cmd run build
```

`build` 包含 TypeScript 类型检查。后端契约变化时，先从 [OpenAPI 0.10.0](../backend/docs/openapi-0.10.0.json) 运行 `npm.cmd run generate:api` 更新 [api-schema.d.ts](src/api-schema.d.ts)。

## 读取与刷新

- 打开资产台账时只读取资产目录。切换页面、选中设备或展开证据时读取所需资料。交换机页每 15 秒刷新一次后台已保存的状态，离开该页后停止轮询。
- 首次目录读取最多 20 页、每页 200 条。未读完时显示截断提示。探测证据按服务端记录顺序每页展示 50 条。
- 各区显示上次读取时间，超过一分钟时提示资料可能过期。筛选和切换对象会取消旧请求。每个请求的超时为 15 秒。
- 网络故障或 503 会显示错误与请求编号，并标明保留的旧数据。401 会清除整个工作台，重新登录后可重新读取。403 会清除被拒绝资源的旧数据。
- `npm test` 使用隔离响应验证 DOM 交互。`tests-live/` 中的历史联调用例依赖本机 8000 端口的只读环境及预置历史；默认 0.10.0 的认证空库使用仓库根目录的 `bootstrap.ps1 test` 验证。
