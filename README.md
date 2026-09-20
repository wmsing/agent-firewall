# agent-firewall

**Agent 双层安全网关**：在 AI Agent 调用外部能力前做统一风控——**L7 HTTP 反向代理**拦恶意写请求 body，**MCP stdio 代理**拦高危 shell 命令。Go 标准库实现，fail-closed。

| 层 | 组件 | 检查对象 | 典型场景 |
|----|------|----------|----------|
| L7 | `agent-firewall`（`:8286`） | POST/PUT/DELETE body | Agent 把 REST 当 Tool |
| MCP | `mcp-firewall`（stdio） | `execute_bash_command` 字符串 | Cursor / Claude 终端工具 |

两层共用 `eval`：**硬规则**（`DROP TABLE`、`TRUNCATE`、`rm -rf` 等）→ 阻断；**语义分**（Mock 或 HTTP 判别器，≥ 0.8）→ 阻断。

## 架构

```text
                    ┌─────────────────────────────────────┐
  Agent HTTP Tool   │  :8286  L7 Reverse Proxy            │
  (POST/PUT/DEL) ──►│  hard rules → semantic score        │──► upstream API
                    │  GET 直通 · body>1MB → 413          │    (e.g. :8090)
                    └─────────────────────────────────────┘

                    ┌─────────────────────────────────────┐
  Cursor MCP Client │  mcp-firewall (JSON-RPC / stdio)    │
  execute_bash_*  ─►│  same eval pipeline                 │──► /bin/bash -c
                    │  BLOCK → isError + reason           │
                    └─────────────────────────────────────┘
```

## 快速启动

**依赖**：Go 1.22+

```bash
git clone https://github.com/wmsing/agent-firewall.git
cd agent-firewall

make check-firewall      # Mock 后端集成测试 + go test
make e2e-pocketbase      # 需本机 pocketbase（或 POCKETBASE=/path/to/pocketbase）
```

手动跑 HTTP 网关：

```bash
go run .                 # 默认 :8286 → 内置 Mock :8287
go run . -backend=false -target http://127.0.0.1:8090
```

构建 MCP 二进制：

```bash
go build -o mcp-firewall ./cmd/mcp-firewall
```

## 配置

复制 `.env.example` → `.env`（勿提交）：

| 变量 | 作用 |
|------|------|
| `EVALUATOR_API_KEY` | 空 = Mock 语义分 |
| `EVALUATOR_API_URL` | 有 Key 时 POST 远程判别 |

## MCP 接入（Cursor）

1. 构建：`go build -o mcp-firewall ./cmd/mcp-firewall`（路径相对于工作区根）。
2. 在项目 `.cursor/mcp.json` 注册：

```json
{
  "mcpServers": {
    "mcp-firewall": {
      "command": "${workspaceFolder}/mcp-firewall",
      "args": []
    }
  }
}
```

若 monorepo 内放在子目录，将 `command` 改为 `${workspaceFolder}/agent-firewall/mcp-firewall`。

3. Agent 规则（建议 `alwaysApply`）：所有终端命令必须走 `execute_bash_command`；`isError: true` 或 `firewall BLOCK` 时停止，勿绕过。

4. 自检：

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_bash_command","arguments":{"command":"rm -rf /"}}}' | ./mcp-firewall
```

应返回 `firewall BLOCK [hard_rule]: rm_rf` 且 `isError":true`。

## 发布（Git 初始化与 Push）

在 **已准备好的 `agent-firewall` 目录**内手动执行（将 `YOUR_ORG` 换成 GitHub 用户名或组织）：

```bash
cd agent-firewall
go mod tidy
git init
git add .
git commit -m "chore: initial import of agent-firewall (L7 + MCP)"
git branch -M main
git remote add origin git@github.com:YOUR_ORG/agent-firewall.git
git push -u origin main
```

HTTPS 远程示例：`https://github.com/YOUR_ORG/agent-firewall.git`。

## License

TBD（发布前添加 LICENSE 文件）。
