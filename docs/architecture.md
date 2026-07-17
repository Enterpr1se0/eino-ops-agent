# Architecture

## Trust boundary

LLM、Prompt、Skill、远程输出和 MCP Client 都不属于可信计算基。唯一能够执行 SSH 的入口是 `service.Service`，它固定执行以下顺序：

1. 从 SQLite 按 `host_id` 解析目标与认证策略，忽略模型提供的任何连接凭据。
2. 规范化请求并计算原始载荷 SHA-256。
3. 使用 Bash AST 和 YAML 规则得到最终风险等级。
4. 永久拒绝 Forbidden；为 Change/Critical 创建审批；仅自动执行 ReadOnly。
5. 仅在实际执行前解密所需 SSH/sudo 密码，获取并发令牌，通过 OpenSSH Transport 执行。
6. 加密原始请求和输出，生成脱敏视图并追加审计事件。

Eino Tool、MCP Tool、HTTP 和 CLI 都是这个 Service 的适配器。

## Packages

- `internal/sshx`：OpenSSH 参数构造、严格 host key、输出上限和连接探测。
- `internal/policy`：Shell AST、内置风险集和 YAML 扩展规则。
- `internal/service`：审批状态机、摘要绑定、执行并发、任务和审计事务。
- `internal/store`：SQLite hosts、runs、approvals、events、chat、加密模型配置与 Eino checkpoints。
- `internal/agent`：Eino ChatModelAgent、强类型 Tools、消息历史、事件流与并发安全的 Runner 热切换。
- `internal/mcpserver`：官方 MCP Go SDK stdio 适配器。
- `internal/httpapi`：本地 HTTP API、SSE 和 React 静态资源。
- `internal/observability`：`slog` 多路 Handler、字段脱敏、JSONL 文件轮转与 Web 内存日志缓冲。
- `internal/skills`：无权限的运维方法论资源。

## Command execution

`ssh_exec` 接收 program 与 args，服务对每个参数进行 POSIX 单引号编码。Go 使用 `exec.CommandContext` 参数数组启动本地 `ssh`，不经过本地 shell。

`ssh_run_script` 将脚本通过 stdin 传给远端 `bash -se`。脚本先由 `mvdan.cc/sh` 完整解析；解析失败、命令替换、动态执行、下载后管道到 shell 等模式会升级为 Critical。

密钥和 ssh-agent 连接固定启用批处理模式：

```text
BatchMode=yes
StrictHostKeyChecking=yes
ConnectTimeout=10
ServerAliveInterval=15
ServerAliveCountMax=2
```

账号密码认证仍使用系统 OpenSSH Client，但将 `BatchMode` 切换为 `no` 并限制每种认证方法只提示一次。密码解密后仅写入权限为 `0600` 的临时 FIFO；静态 AskPass helper 读取指定长度，密码本身不出现在命令行、环境变量或普通临时文件中，执行结束立即销毁通道。

提权是 `ExecRequest.elevated` 的结构化属性，不是任意命令字符串。Policy 会无条件追加 `managed_sudo` 命中并升级为 Critical；批准后 Transport 才按主机配置包装为 `sudo -n -- bash -c ...` 或 `sudo -S -p '' -- bash -c ...`。sudo 密码只拼接到远端 stdin，不进入请求摘要、审计 JSON 或模型工具参数。

## Approval state machine

```text
created ── ReadOnly ──> running ──> completed / failed
   │
   ├── Change/Critical ──> approval_required ──> approved ──> running
   │                                     └─────> rejected / expired
   └── Forbidden ──> denied
```

Critical 审批除摘要外还需要动态 challenge 和原因。审批写入后，服务再次解密原始载荷并重新计算摘要，避免 TOCTOU 或载荷替换。

Eino Agent 请求会在 context 中启用 blocking approval。Service 创建审批后先通过 SSE notifier 立即通知 Web，再让原 Tool goroutine 轮询持久化的 approval/run 状态；批准接口负责执行精确载荷，完成后结果回到原 Tool Call，拒绝说明则以 `operator_instruction` 回到模型。CLI、MCP 和直接 HTTP 执行保持非阻塞的 `approval_required` 返回契约。等待期间每 15 秒发送一次 SSE approval heartbeat。

HTTP Chat Handler 使用保留 request logger/value、但移除浏览器取消信号的后台 context，并额外施加 30 分钟上限。浏览器断开后只停止 SSE 写入，原 Agent/Tool goroutine 继续等待审批；Runtime 按 session ID 记录 active 状态并拒绝同会话并发运行。Web 刷新后通过 `GET /api/v1/chat/{id}/state` 同步 active 状态和持久化消息，直到原循环完成。活动会话不能删除。该机制覆盖页面刷新和临时网络中断，不承诺跨服务进程重启恢复内存中的 Agent Loop。

## Sequential task plans

复杂任务通过 Eino 专用的 `ops_plan_create`、`ops_plan_get` 和 `ops_plan_step_update` 三个强类型 Tool 编排。计划和步骤分别写入 `agent_plans`、`agent_plan_steps`，session ID 只取可信 Go context，模型不能为其他会话读写计划。创建时只允许 2–8 个不重复步骤，第一步自动进入 `in_progress`；Store 在单个 SQLite 事务中只接受当前步骤的 `completed` 或 `blocked` 转移，完成后自动激活下一步，因而数据库层始终最多只有一个进行中步骤。

计划创建与每次状态转移均写入审计。Chat state 同时返回消息、后台运行状态和最新计划，Web 使用同一恢复轮询展示总进度、当前步骤与完成证据。Agent Loop 达到迭代上限不会删除计划；下一条 `continue` 可调用 `ops_plan_get` 继续当前步骤。计划是编排状态而非额外权限，所有 SSH Tool 仍独立通过 Policy、审批和加密审计。

## Audit storage

`runs.request_json`、stdout 和 stderr 的可检索字段均为脱敏视图；对应原文采用 AES-256-GCM 写入 cipher 字段。MCP/Eino 历史工具永远不会返回 cipher 或解密内容。只有本地审批和显式 `audit show --raw` 会解密。

每次运行还会产生独立事件：`command_started`、`approval_requested`、`approval_granted/rejected`、`command_completed/denied`、`task_cancelled` 等。

## Server observability

服务端日志与执行审计是两条独立链路：Audit 是 SQLite 中不可替代的安全证据，Server Logs 用于排查控制面运行状态。应用统一调用标准库 `log/slog`，初始化时通过 MultiHandler 分发到终端、JSONL 轮转文件和进程内环形缓冲区。`GET /api/v1/logs` 只读取环形缓冲区，Web 轮询该接口不会再次写入请求日志，避免自激式增长。

HTTP Middleware 为请求生成 `request_id` 并记录 method、path、status、耗时、响应字节和来源 IP；该 logger 通过 context 传递给 Agent、Policy、Approval 与 SSH 层，因此一次请求的跨层事件可以关联检索。模型输入、reasoning token、HTTP body、命令参数、脚本和远端输出均不进入服务日志，只记录长度、计数、ID 与最终状态。Handler 对包含 password、secret、token、API key、content、stdout/stderr 等名称的属性执行第二层替换。Debug 日志默认关闭，可通过配置或 `OPS_AGENT_LOG_LEVEL=debug` 启用。

## Conversation persistence

每个新对话由后端生成 session ID，用户消息、最终 Assistant 文本和带 `tool_name` 的脱敏工具结果写入 `chat_messages`，Eino checkpoint 使用同一 session ID。Web 恢复历史时重建工具结果卡片；模型上下文查询只选择 user/assistant，避免没有对应 ToolCall ID 的展示记录污染协议上下文。会话索引按最后事件时间排序，标题取第一条用户消息；删除会话会在同一 SQLite 事务中删除消息和对应 checkpoint，执行证据仍保留在独立的 runs 与 audit_events 中。

Runner 在调用工具前通过 Go context 绑定当前 session ID，Service 创建 Run 时只从可信 context 读取该值，模型工具参数不能伪造会话归属。异步 Task 会把该值复制到脱离 HTTP 请求生命周期的后台 context。Audit 页面按 `runs.session_id` 分组；CLI、MCP、HTTP 直调和升级前的历史记录显示在 Direct / Legacy 分组。

## Model provider routing

模型提供商统一映射为 Eino 的 OpenAI-compatible ChatModel，可保存 OpenAI、DeepSeek、Ollama 和自定义兼容端点。API Key 在进入 SQLite 前使用与审计数据相同的 AES-256-GCM 主密钥加密，对外只返回 `has_api_key`。

SQLite 使用部分唯一索引保证最多只有一个 active provider。切换时服务更新 active route，构建新的 ChatModelAgent 与 Runner，再通过互斥锁原子替换运行时指针；已经取得旧 Runner 的请求可以正常结束，新请求使用新配置。没有 active provider 时才回退到 `OPENAI_*` 环境变量。

模型发现统一请求配置 Base URL 下的 `GET /models`，兼容 OpenAI 标准的 `data[].id`，同时容忍部分实现的 `models[]` 包装。请求最长 15 秒、响应最大 2 MiB，并禁止 HTTP 重定向，避免 Authorization Header 被转发到其他地址；上游错误在返回 Web 前会经过密钥替换和通用脱敏。

所有保存、发现与测试流程复用同一 Base URL 规范化函数：无协议的 loopback、私网 IP、`.local` 与单标签主机补全为 HTTP，公网域名补全为 HTTPS，并移除末尾误填的 `/models` 或 `/chat/completions`。包含凭据、查询参数或 fragment 的 URL 会被拒绝。

模型测试可以使用已保存配置，也可以使用尚未落库的表单配置。后端复用加密 Key 或请求中的临时 Key，通过对应 ChatModel 发送 `Hello`；HTTP 调用成功且 Assistant Content 去除空白后非空才返回 Healthy，空响应与协议错误均视为失败。

## Runtime settings

Web 配置中心把模型提供商、SSH 主机和系统设置收敛到同一入口。`system_settings` 单行表保存 Agent 最大模型迭代数，默认 20，API 只接受 5–50；每次修改都会写入 `system_settings_updated` 审计事件。保存后 Runtime 构建新的 ChatModelAgent/Runner 并原子替换指针，因此新请求立即使用新的循环预算，已经取得旧 Runner 的执行不会被中断。
