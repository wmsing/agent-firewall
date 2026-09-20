# 防火墙 MVP

## 验收

```bash
make check-firewall
```

## 本 spec 管什么

- `:8286` 反向代理 → `:8287`；**POST/PUT/DELETE** 读 body（重置后转发）
- **硬规则**命中 → 403；语义分 ≥ 0.8 → 403 + 日志（Mock 或 HTTP，见 `task_evaluator.md`）
- 代码：`firewall/main.go` · `proxy.go` · `evaluator.go`

## 已实现（Done）

- Mock / HTTP 判别器、fail-closed、默认同进程假后端（`-backend`）
- 手动 curl 见 `firewall/README.md`（调试用）

## 范围外

Jev/真实模型、body 大小上限、生产审批、YAML 规则、CI。

---

## 原始需求（归档，改功能时不必读）

1. 监听 `:8286`，转发到后端（如 `:8287`）。
2. 转发前拦截 POST/PUT/DELETE，提取 Body 并重置后再转发。
3. 两层检查：硬规则（DROP TABLE、rm -rf、TRUNCATE 等）→ 403；`RiskEvaluator.Evaluate` Mock 0–1 分。
4. 分 ≥ 0.8 → 403 JSON + 日志；< 0.8 → `httputil.ReverseProxy` 转发。
5. `go run .` 可跑；附 curl 说明。
