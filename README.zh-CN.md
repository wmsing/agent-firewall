# agent-firewall

**语言**：[English](README.md) | **简体中文**

> **一句话**：Agent 动 HTTP 或跑 shell 之前，先过同一套风控；拦不住就不放行（fail-closed）。

**仓库**：<https://github.com/wmsing/agent-firewall>

双入口 **HTTP `:8286`** 与 **MCP stdio**（`mcp-firewall`）共用 **`eval`**：先 [`eval/rules.json`](eval/rules.json) 硬规则，再语义打分（Mock / HTTP / **TypeSafe Jev**）。

![Architecture](docs/images/architecture.png)

---

## 目录

| 我想… | 跳到这里 |
|--------|----------|
| 克隆并跑测试 | [30 秒上手](#30-秒上手) |
| 起 HTTP 网关 | [L7 网关](#l7-网关) |
| 接 Cursor MCP | [MCP（Cursor）](#mcpcursor) |
| 配语义判别 API | [环境变量](#环境变量) |
| 看懂两层干啥 | [两层一览](#两层一览) |
| 看交互架构图 | [两层一览](#两层一览) · [打开 HTML](#架构图本地查看) |
| OWASP / 威胁模型 | [Threat Model](#threat-model--owasp-for-llm-alignment) |
| 改硬规则 | [两层一览](#两层一览) · `eval/rules.json` |

---

## 两层一览

| 层 | 跑什么 | 查什么 | 啥时候用 |
|----|--------|--------|----------|
| **L7** | `agent-firewall` → `:8286` | POST/PUT/DELETE 的 body | Agent 把 REST 当 Tool |
| **MCP** | `mcp-firewall`（stdio） | `execute_bash_command` 里的命令串 | Cursor / Claude 终端工具 |

**同一套 `eval`**

1. **硬规则** — `DROP TABLE`、`TRUNCATE`、`rm -rf` 等 → 直接 BLOCK（规则表 [`eval/rules.json`](eval/rules.json)，`go:embed` 打进二进制；改后重新 `go build` 或重启 MCP 进程）  
2. **语义分** — Mock，或 HTTP 判别器；分数 **≥ 0.8** → BLOCK  

```text
  HTTP (POST/PUT/DEL) ──► :8286 ──► hard rules → score ──► 上游 API
  GET 直通 · body > 1MB → 413

  MCP execute_bash_* ──► mcp-firewall ──► 同一 eval ──► /bin/bash -c
  BLOCK → isError + reason
```

**架构图（Archify）**：源稿 [`docs/diagrams/agent-firewall.architecture.json`](docs/diagrams/agent-firewall.architecture.json) · 自包含页 [`docs/diagrams/agent-firewall-architecture.html`](docs/diagrams/agent-firewall-architecture.html)

### 架构图本地查看

GitHub 网页**不会**执行仓库里的 HTML，需在克隆后用浏览器打开：

```bash
open docs/diagrams/agent-firewall-architecture.html   # macOS
# Linux: xdg-open docs/diagrams/agent-firewall-architecture.html
# Windows: start docs/diagrams/agent-firewall-architecture.html
```

或在 Finder / 资源管理器中双击该文件。改图后可用 Archify 从 JSON 重新 `deliver` 生成 HTML。

---

## Threat Model & OWASP for LLM Alignment

`agent-firewall` is engineered to defend against key risks defined in the **OWASP Top 10 for LLM Applications**:

| OWASP LLM Category | Attack Vector | Firewall Defense Mechanism |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Malicious payloads via HTTP tools | Semantic risk scoring (TypeSafe Jev) → 403 Forbidden |
| **LLM06: Excessive Agency** | Agent running destructive host commands | MCP Executor blocks `rm -rf`, dangerous Git ops |
| **LLM02: Sensitive Info Disclosure** | Unauthorized credential access | Hard-rule regex & semantic interception |
| **LLM04: Model DoS** | OOM attacks via oversized payloads | Strict 1MB payload ceiling → 413 Payload Too Large |

---

## 30 秒上手

**需要**：Go **1.22+**

```bash
git clone https://github.com/wmsing/agent-firewall.git
cd agent-firewall
make check-firewall    # 集成测试 + go test
```

可选：

```bash
make test              # 仅单元测试
```

### PocketBase 端到端

1. 安装 [PocketBase](https://pocketbase.io/) 并保证 `pocketbase` 在 PATH，或 `POCKETBASE=/path/to/pocketbase`。
2. 执行 `make e2e-pocketbase`（见 `docs/spec/task_e2e_pocketbase.md`）：起 `:8090` 后端 + 防火墙，验证放行、硬规则 403、语义 403 与 `"action":"BLOCK"` 日志。

---

## L7 网关

```bash
go run .                                    # :8286 → 内置 Mock :8287
go run . -backend=false -target http://127.0.0.1:8090
```

---

## MCP（Cursor）

### Checklist

- [ ] 复制 `.cursor/mcp.json.example` → `.cursor/mcp.json`（`scripts/run-mcp-firewall.sh`；改 **Cursor Agent 规则** 后 **Reload MCP**；改 **硬规则** 见 `eval/rules.json` 后重建/重启 MCP）
- [ ] 工作区是上级 monorepo `jev_demo`：用 `jev_demo/.cursor/mcp.json`（已含 `agent-firewall/scripts/...`），勿用顶层 `go run ./cmd/mcp-firewall`
- [ ] 生产/CI 仍可用二进制：`go build -o mcp-firewall ./cmd/mcp-firewall`，`command` 指该文件

见 `.cursor/mcp.json.example`（自动识别工作区是 `agent-firewall` 还是上级 monorepo 里的 `jev_demo`）

- [ ] monorepo 若仍报错：确认日志里不是 `stat .../jev_demo/cmd/mcp-firewall`（旧配置）；Reload MCP
- [ ] MCP 报 `go: command not found`：在 `mcp.json` 加 `env.PATH`（含 Homebrew），或把 `command` 改成 `which go` 的绝对路径
- [ ] Agent 规则（建议 `alwaysApply`）：终端**只**走 `execute_bash_command`；`isError: true` 或 `firewall BLOCK` → **停**，别绕过

**自检**（应看到 `firewall BLOCK [hard_rule]: rm_rf` 且 `isError":true`）：

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_bash_command","arguments":{"command":"rm -rf /"}}}' | go run ./cmd/mcp-firewall
```

---

## 环境变量

复制 `.env.example` → `.env`（**不要提交**）

| 变量 | 不设 / 空 | 设了 |
|------|-----------|------|
| `TYPESAFE_API_KEY` | — | **优先**：原生 TypeSafe `/v1/systemone`（Jev） |
| `TYPESAFE_BASE_URL` | `https://api.typesafe.ai` | API 根地址 |
| `TYPESAFE_DEFAULT_MODEL` | `jev-latest` | System One 模型 |
| `TYPESAFE_EVALUATOR_TIMEOUT` | `2s` | TypeSafe 单次判别超时 |
| `EVALUATOR_API_KEY` | 无 TypeSafe Key 时 Mock | 通用 HTTP 判别 |
| `EVALUATOR_API_URL` | — | 有 `EVALUATOR_API_KEY` 时 POST 到此 URL |

---

## License

尚未选定许可证（仓库内暂无 `LICENSE`）。对外使用前请补文件并改本节。
