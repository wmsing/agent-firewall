# TASK: 升級 README.md 開源展示規範

## 1. 目標
將 agent-firewall 的根目錄 `README.md` 升級為工業級開源水準，加入架構圖、OWASP LLM 風險防禦對齊矩陣，以及真實的 TypeSafe Jev 攔截戰報。

## 2. 結構與排版要求
1. **頂部架構區**：
   - 在簡介與定位下方，嵌入架構圖：`![Architecture](docs/images/architecture.png)`。
   - 簡述雙入口（HTTP :8286 + MCP stdio）與共享 eval 核心機制。
2. **安全防禦矩陣（對齊 OWASP Top 10 for LLM）**：
   - 插入對照表格，覆蓋：
     - `LLM01: Prompt Injection`（TypeSafe 語義評分 -> 403）
     - `LLM06: Excessive Agency`（MCP 阻斷 rm -rf、高危 Git）
     - `LLM02: Sensitive Info Disclosure`（敏感路徑與資料過濾）
     - `LLM04: Model DoS`（嚴格 1MB Payload 限制 -> 413）
3. **實戰攔截戰報（Live Interception Showcase）**：
   - 加入真實終端攔截展示區塊，貼出真實輸出的結構化日誌（Action: BLOCK, score=1.00, HTTP 403）。
4. **保留原有驗證步驟**：
   - 保留現有的 `make check-firewall`、`make e2e-pocketbase` 與 PocketBase 聯調步驟。

## 3. 驗收標準
- `README.md` 結構清晰，排版具備專業資安工程質感。
- 圖片路徑正確，表格與程式碼區塊無語法錯誤。
