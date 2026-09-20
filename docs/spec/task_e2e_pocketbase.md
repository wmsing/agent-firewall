# task_e2e_pocketbase: PocketBase 端到端接入与防御验证

## 目标
让 Go Firewall 代理真实的 PocketBase 实例，并验证正常 CRUD 与恶意越权写入。

## 操作流程
1. 启动 PocketBase：监听 127.0.0.1:8090。
2. 启动 Firewall：
   - 监听端口：:8286
   - 目标后端：-backend http://127.0.0.1:8090
3. 验证端到端场景：
   - 场景 A（正常业务）：向 :8286 发起正常创建用户/记录请求 → 放行，PocketBase 成功落库并返回 200/201。
   - 场景 B（硬规则注入）：Payload 包含 "DROP TABLE" 或 "rm -rf" → 网关 403 阻断，PocketBase 毫无感知。
   - 场景 C（语义高危）：Payload 触发打分拦截 → 网关 403 阻断 + 输出 slog JSON 告警。

## 产出
- `scripts/e2e-pocketbase.sh`（`make e2e-pocketbase`）。
- 更新 README 说明如何配合真实后端启动。
