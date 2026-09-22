# Task: HTTP 远程判别器

## 验收

```bash
make check-firewall
```

含 Mock 集成测试 + `go test`（HTTP JSON 与 300ms 超时）。

## 本 spec 管什么

- 无 `EVALUATOR_API_KEY` 且无 `TYPESAFE_API_KEY` → **Mock**
- 有 `EVALUATOR_API_KEY` + `EVALUATOR_API_URL` → 先 `HTTPRiskEvaluator` POST 该 URL
- 若同时有 `TYPESAFE_API_KEY` → HTTP 失败（超时/非 200/解析错误）时 **fallback** TypeSafe；HTTP 成功则用 HTTP 分数
- 仅 `TYPESAFE_API_KEY`（无 `EVALUATOR_*`）→ 仅 TypeSafe
- 请求：`{"content":"..."}` · 响应：`{"score":0.1,"reason":"..."}` · Header：`Authorization: Bearer <key>`
- HTTP 单次 **300ms** timeout；fallback 后 TypeSafe 用 `TYPESAFE_EVALUATOR_TIMEOUT`（默认 2s）
- 若 HTTP 与 TypeSafe 均不可用 → `Assess` **fail-closed**

## 环境

见 `firewall/.env.example`。
