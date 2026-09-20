# task_harden: 生产加固与结构化日志

## 验收

```bash
make check-firewall
```

含 >1MB POST → **413**；`go test` 仍通过。

## 本 spec 管什么

- Mutating 请求 body：**MaxBytesReader 1MB**，超限 **413**（非 403）
- 审计：**slog JSON**（stderr），字段 `client_ip`、`method`、`path`、`reason`、`action`（`ALLOW`/`BLOCK`）、有则 `risk_score`

## 已实现

- 改动在 `firewall/proxy.go`；启动时在 `main.go` 设 `slog` JSON handler
