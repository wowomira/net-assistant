# 团队协作

## 分工与基线

- 后端 `0.10.0`；契约 `net-assistant/backend/docs/openapi-0.10.0.json`。
- 前端仍是阶段性只读工作台；本轮只更新类型及生成入口，不改变 UI。
- 后端负责认证、API、协议、迁移；前端继续接登录、改密、会话失效和受控终端。
- “填入命令”“预览”“确认”“执行”保持分离；不可为方便前端而关闭认证、CSRF 或主机密钥验证。
- 每人独立 clone、独立 `.runtime`、独立账户，不共享工作库或私钥。

## 提交流程

```powershell
git pull --ff-only
git switch -c codex/describe-your-change
python scripts/workspace.py setup --index-url https://pypi.org/simple
python scripts/workspace.py init
python scripts/workspace.py test
git add <明确修改的源码文件>
git commit -m "feat: describe your change"
git push -u origin HEAD
```

通过 Pull Request 审阅，不要两人同时直接改主分支。
公开仓库可直接克隆阅读，通过分支／Fork 和 Pull Request 协作；直接写入权限仍由仓库管理员按需授予，不因公开而允许任何人直接推送主分支。

## 前端与契约

改 `net-assistant/frontend/src`，不要把 `.runtime/frontend/src` 当成正式源码；
后者是独立构建副本，`setup` / `test` 会同步源码。
在前端源码目录执行 `npm run generate:api`、`npm run typecheck` 和 `npm test`。
生成入口已经从旧 0.6.0 改为 0.10.0。API 变更必须同步契约、类型和对接说明。

建议先用 README 的同源构建模式联调。原 Vite 开发代理仍指向 8000；
如用 8001 后端须单独调整，登录 POST 的 Origin 也须一致，不能以放宽同源校验掩盖问题。
源码版本不是正在运行的旧 API 版本，务必核对 `/openapi.json`。

## 数据与迁移

- `init` 仅创建新开发库；已有库只检查，`serve`/`check` 不迁移。
- 新 migration 先用临时库、备份及恢复副本验证。已发布 revision 不原地改写。
- 旧工作库早期 0006 的六处差异是独立修复任务，本轮未修复或回滚。
- 旧后台会自动加载共用源码中的迁移；后续必须隔离源码开发，不在旧工作服务目录做生产试验。
- `test --local-tools` 仅运行真实本机/回环工具；实网扫描必须重新核对真实授权。

## 合并前

`python scripts/workspace.py test`、`check` 均应通过；检查 `git diff --cached --stat`，
确认数据库、密钥、本机配置、依赖目录、报告、构建和缓存未提交。
GitHub Actions 的配置存在不等于运行通过，查看具体运行结果。
