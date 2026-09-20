# Task: HTTP 远程判别器

## 验收

```bash
make check-firewall
```

含 Mock 集成测试 + `go test`（HTTP JSON 与 300ms 超时）。

## 本 spec 管什么

- 无 `EVALUATOR_API_KEY` → **Mock** 启动
- 有 Key → `HTTPRiskEvaluator` POST `EVALUATOR_API_URL`
- 请求：`{"content":"..."}` · 响应：`{"score":0.1,"reason":"..."}` · Header：`Authorization: Bearer <key>`
- 单次调用 **300ms** context 超时（超时 → fail-closed 403）

## 环境

见 `firewall/.env.example`。
