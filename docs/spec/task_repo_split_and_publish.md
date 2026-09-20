# TASK: agent-firewall 仓库拆分与开源发布

## 目标

将 `jev_demo/firewall/`（L7 反代 + `cmd/mcp-firewall`）抽成可独立发布的开源仓库 **agent-firewall**，本 monorepo 保留 `firewall/` 直至 cutover 完成。

## 独立仓库文件清单

```text
agent-firewall/
├── README.md                 # 开源说明（定位、拓扑、快速启动、MCP）
├── Makefile                  # check-firewall · e2e-pocketbase
├── .gitignore                # .env、二进制、日志、pb_data
├── .env.example
├── go.mod / go.sum
├── main.go                   # HTTP 网关入口
├── proxy.go / proxy_test.go
├── e2e_test.sh               # PocketBase 联调（需本机 pocketbase）
├── eval/
│   ├── evaluator.go
│   └── evaluator_test.go
├── cmd/mcp-firewall/
│   ├── main.go
│   ├── mcp.go
│   └── mcp_test.go
└── scripts/
    ├── check-firewall.sh     # 集成验收 + go test
    └── e2e-pocketbase.sh    # 包装 e2e_test.sh
```

**不纳入**：`test.txt`、`.env`、编译产物（`mcp-firewall`、临时 `jev_*`）、`pb_data/`、jev 专用 `docs/spec/*`（行为说明已写入 README）。

## 模块路径

- 独立仓库 Go module：`github.com/wmsing/agent-firewall`（发布前可改为你的 org）。
- import：`github.com/wmsing/agent-firewall/eval`。

## 验收

在 **agent-firewall 仓库根目录**：

```bash
make check-firewall
make e2e-pocketbase   # 需 PATH 中有 pocketbase，或 POCKETBASE=/path/to/pocketbase
```

## Cutover（jev_demo，后续 PR）

1. `go.mod` 中 `replace` 或 git submodule 指向新仓库；或继续 vendoring 同步。
2. `.cursor/mcp.json.example` 二进制路径改为新构建产物。
3. `scripts/check-firewall.sh` 改为调用子模块 / 删除重复 `firewall/`。

## Done

- [x] 本 spec + `agent-firewall/` 导出目录（见仓库根 `agent-firewall/`）
- [ ] 远程 GitHub 创建空仓库并 push（见 README「发布」一节，手动执行）
- [ ] jev_demo cutover（可选）
