我想把当前 firewall 和 mcp-firewall 相关的核心代码独立抽取为一个准备开源的独立项目仓库（命名为 agent-firewall）。请帮我按规范执行：
1. 创建任务卡：生成 docs/spec/task_repo_split_and_publish.md。
2. 整理独立目录结构：规划好独立仓库所需的文件清单，确保包含 Go 源码、单测、Makefile、.gitignore（严格排除 .env、临时二进制与日志）。
3. 撰写开源规范 README.md：包含项目定位（L7 HTTP 反代 + MCP 安全代理双层防御）、架构 ASCII 拓扑图、快速启动（make check-firewall / make e2e-pocketbase）以及 MCP 接入指南。
4. 给出最终的 Git 初始化与 Push 命令，供我手动在终端执行。