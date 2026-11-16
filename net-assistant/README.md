# 网维助手 · 实际巡检工程

本目录是实际项目，不是队友阅读用的说明网站。

> **2026-11-16 协作入口：后端 0.10.0（平台认证与受控 SSH）。**
> 新协作者先读仓库根 `README.md`，用 `scripts/workspace.py` 隔离启动；
> 下文绝对路径及版本状态为历史记录，旧前端尚无登录页。

## 当前入口

- 后端 / 探测 / SQLite / Windows 每日工作服务：
  `<checkout-or-user-tool-path>`
- 新增简单只读前端（React / TypeScript）：
  `<checkout-or-user-tool-path>`
- 本轮验收：
  `<checkout-or-user-tool-path>`

运行关系：

```text
每日独立工作进程 / 本机手动CLI
    → 探测授权目标
    → 保存巡检SQLite、建立资产关联
    → FastAPI读取
    → /console/ React工作台显示
```

前端不产生探测结果，开发助手的操作不算项目自动能力。
目前网页只读；没有网页内扫描、授权Agent、CPU/内存/进程、完整告警恢复与自动修复。
启动方式和实际验证范围以各模块说明与验收记录为准。
