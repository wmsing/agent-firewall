# TASK: 解耦硬拦截规则至独立 rules.json (零依赖嵌入)

## 1. 目标
将硬编码在 Go 源码中的 `hardRules` 正则列表抽取到独立的 `rules.json` 文件中，利用标准库 `embed` 打包，兼顾“配置文件易读易改”与“纯标准库零外部依赖单二进制”优势。

## 2. 规范与改动清单
1. **新建配置文件 `eval/rules.json`**：
   - 提取现有全部规则：`drop_table`, `truncate`, `rm_rf`, `git_danger`, `git_supply`。
   - 保持正则转义正确。
2. **重构规则加载逻辑（如 `eval/rules.go`）**：
   - 使用 `//go:embed rules.json` 静态嵌入内容。
   - 在 `init()` 或初始化方法中一次性 `json.Unmarshal` 并执行 `regexp.Compile`。
   - 若解析或正则语法非法，直接 panic 暴露配置错误（Fail-Fast）。
3. **保持接口向前兼容**：
   - `eval.Assess()` 的判定逻辑与返回契约完全不变。

## 3. 验收标准
- 运行 `make check-firewall` 必须一次性全绿通过。
- 随意在 `rules.json` 添加一条测试规则（如匹配 `secret_token`），现有拦截单测能直接识别生效。
