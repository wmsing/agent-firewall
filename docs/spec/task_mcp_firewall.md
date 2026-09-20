# TASK: MCP 安全执行代理 (MCP Safe Executor)

## 1. 目标
构建一个符合 Model Context Protocol (MCP) 规范的轻量本地服务（基于 Go），复用现有 `firewall/evaluator.go` 的安全检查管道，拦截 Cursor/Claude 尝试执行的危险终端命令。

## 2. 交互拓扑
Cursor Composer / Agent (MCP Client)
         │
         │  JSON-RPC over stdio
         ▼
[ mcp-firewall / Go ]
   ├─ Tool: `safe_execute_command(command)`
   ├─ 安全安检: 复用 evaluator 的硬规则 + 语义打分 (0.8 阈值)
   ├─ 判定阻断: 返回 MCP isError=true + 阻断告警与原因
   └─ 判定放行: 执行真实 exec.Command 并返回 stdout/stderr
         │
         ▼
    Mac 真实终端环境

## 3. 改动与任务清单
1. **新建子模块目录**：`mcp_firewall/`（或在 `firewall/cmd/mcp/`）。
2. **MCP 工具注册**：
   - 工具名：`execute_bash_command`
   - 输入参数：`{"command": "string"}`
3. **安全管道复用**：
   - 检查 `command` 字符串：硬规则 (rm -rf, 敏感文件读取, drop 等) -> 直接阻断报错。
   - 语义评分：调用已有 `RiskEvaluator` 评估命令风险分 -> 分数 >= 0.8 阻断。
4. **输出验证**：
   - 在 `.cursor/mcp.json` 中配置该 Go 二进制。
   - 在 Cursor Agent 模式下触发执行高危命令，确认被网关阻断。

## 4. 验收标准
- 编译生成二进制 `mcp-firewall`。
- 本地 `echo '{"jsonrpc":"2.0",...}' | ./mcp-firewall` 单测通过。
- Cursor 能成功识别该 MCP 工具，输入危险指令时返回拒绝提示，且终端不执行。
