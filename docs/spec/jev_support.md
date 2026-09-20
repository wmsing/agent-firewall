# Task: TypeSafe Jev 原生语义判别

## 验收

```bash
make check-firewall
```

## 本 spec 管什么

- 设 `TYPESAFE_API_KEY` → `TypeSafeEvaluator` POST `{base}/v1/systemone`（默认 `https://api.typesafe.ai`，模型 `jev-latest`）
- 可选 `TYPESAFE_BASE_URL`、`TYPESAFE_DEFAULT_MODEL`
- 未设 TypeSafe Key → 保持原逻辑：`EVALUATOR_*` 或 Mock
- TypeSafe 默认 **2s** 超时（`TYPESAFE_EVALUATOR_TIMEOUT`）；通用 `EVALUATOR_*` 仍为 **300ms**
- 判别错误 → fail-closed（与 `task_evaluator.md` 一致）
- `make check-firewall` 会 **unset** 上述 Key，只用 Mock

## 实现

- `eval/typesafe_evaluator.go` · 工厂：`eval.NewRiskEvaluator`
