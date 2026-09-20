# Jev 工单分诊

## 验收

```bash
make check-jev
```

通过 = 终端出现 `offline OK`。

## 本 spec 管什么

- `@jev.fn` 工单 → `Triage`（部门 / 是否紧急 / 挫败 0–2）
- **默认离线**；`--live` 才调 TypeSafe（要 `TYPESAFE_API_KEY`）

## 细节

| 字段 | 值 |
|------|-----|
| `department` | `billing` · `technical` · `sales` |
| `is_urgent` | bool |
| `frustration` | 0–2 |

代码：`jev/example.py` · Key 模板：`jev/.env.example`
