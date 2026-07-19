# Architecture

## Trust boundary

LLM、Prompt、Skill、远程输出和 MCP Client 都不属于可信计算基。唯一能够执行 SSH 的入口是 `service.Service`，它固定执行以下顺序：

1. 从 SQLite 按 `host_id` 解析目标与认证策略，忽略模型提供的任何连接凭据。
2. 规范化请求并计算原始载荷 SHA-256。
3. 使用 Bash AST 和 YAML 规则得到最终风险等级。
4. 永久拒绝 Forbidden；为 Change/Critical 创建审批；仅自动执行 ReadOnly。
5. 仅在实际执行前解密所需 SSH/sudo 密码，获取并发令牌，通过审批绑定的内置 SSH Transport 执行。
6. 加密原始请求和输出，生成脱敏视图并追加审计事件。

Eino Tool、MCP Tool、HTTP 和 CLI 都是这个 Service 的适配器。预期失败被规范化为带 `code/retryable/next_action` 的 Tool 结果；只有上下文取消或内部持久化损坏会成为 ToolNode fatal error。

这里的 MCP Tool 分为两个方向。`ops-agent mcp` 把受控 SSH Service 暴露为 stdio MCP Server，因此完整复用 Policy、审批和审计。管理员配置的外部 MCP Server 则属于独立信任域：它的工具在远端/子进程自身权限下执行，不自动继承 SSH Policy。Web 会明确提示该边界，只有启用状态为 ready 且未被 func 管理单独关闭的外部工具才进入主 Agent，评审 SubAgent 仍保持无 Tool。

Web/API 位于单管理员认证边界之后。首次密码由环境变量初始化为 Argon2id 哈希；后续请求使用只保存哈希的服务端 Session、HttpOnly/SameSite Cookie 和 CSRF Token。MCP stdio 与 CLI 仍属于本机进程边界，不复用浏览器 Cookie。

对于确定性 Policy 已判为 Change 或 Critical 的请求，Service 在创建审批后异步调用 `CommandExplainerAgent`。它是一个 `MaxIterations=1`、无 Tool 的独立 Eino `ChatModelAgent`，只返回面向操作员的机制、影响、风险提示和回滚说明。它不能修改确定性风险、批准请求或执行命令；失败按 degraded/unavailable 持久化并继续走原审批路径。

## Packages

- `internal/sshx`：进程内 SSH 认证、严格 host key、SFTP、ProxyJump、输出上限和连接探测。
- `internal/policy`：Shell AST、内置风险集和 YAML 扩展规则。
- `internal/service`：审批状态机、摘要绑定、执行并发、任务、审计事务，以及外部 MCP Client Session 与动态工具生命周期。
- `internal/store`：SQLite hosts、runs、approvals、events、chat、加密模型/MCP 配置与 Eino checkpoints。
- `internal/agent`：Eino ChatModelAgent、强类型 Tools、消息历史、事件流与并发安全的 Runner 热切换。
- `internal/mcpserver`：官方 MCP Go SDK stdio 适配器。
- `internal/httpapi`：本地 HTTP API、SSE 和嵌入 Go 二进制的 React 静态资源。
- `internal/observability`：`slog` 多路 Handler、字段脱敏、JSONL 文件轮转与 Web 内存日志缓冲。
- `internal/skills`：可上传、永久删除和启停的无权限运维方法论注册表。

## Dynamic extensions

Skill Registry 位于控制面数据目录，每个 Skill 目录必须包含 `SKILL.md`，启用状态写入独立 `skill.json`。管理员列表包含全部 Skill；`ops_skill_list/get` 只读取启用项。状态修改后主 Eino Agent 和 OpsPilot 自身的 MCP Server 看到一致的动态集合，删除是不可恢复的物理删除。

主 Agent 的 func 启用状态保存在 `agent_tool_settings`。未写入状态的 func 默认启用；管理员可在 Loaded functions 中逐项关闭或重新启用。每次修改都会写入审计并重建 Eino runner，关闭项仍保留在管理目录中，但不会传给 ChatModel，也不会注册到 ToolNode。

外部 MCP 配置保存在 `mcp_servers`。command、args、cwd、URL 和秘密键名是可管理元数据，环境变量与 HTTP Header 的完整映射整体使用 AES-256-GCM 加密。启动时 Service 尝试连接所有 enabled 配置；单个服务器失败只记录 `error` 状态和结构化日志，不阻止控制面启动。

stdio 通过 `exec.Command(command,args...)` 启动，不解析 Shell；Streamable HTTP 使用官方 MCP Go SDK transport。连接成功后分页执行 `tools/list`，把服务器 JSON Schema 转为 Eino ToolInfo，并生成不超过模型限制的稳定名称 `mcp__<server-id-hash>__<sanitized-tool-name>`。动态 wrapper 每次调用都重新检查服务器的 ready Session，因此 Disable/Delete/重连失败会立即阻止旧 Runner 中的残留句柄；随后 Runtime 热重载会从模型函数 Schema 中移除它。调用结果限制为 128 KiB，并记录不含参数或输出的 `mcp_tool_called` 审计事件。

## Command execution

`ssh_exec` 接收 program 与 args，服务对每个参数进行 POSIX 单引号编码，并通过 `golang.org/x/crypto/ssh` 在进程内建立连接，不调用本地 SSH 程序或 shell。

`ssh_run_script` 将脚本通过 stdin 传给远端 `bash -se`。脚本先由 `mvdan.cc/sh` 完整解析；解析失败、命令替换、动态执行、下载后管道到 shell 等模式会升级为 Critical。

无 PTY 的交互式 Shell、编辑器与 `systemctl edit` 会在 Service 层拒绝；apt/dnf/yum/pacman 的变更操作必须显式提供对应非交互参数。脚本、argv、环境和路径还有独立大小与格式上限，检测到秘密的环境变量不会进入执行请求。

## Transactional files and Workspace

`ssh_file_read` 在同一次受审计操作中返回有界内容、mode/owner/mtime 与 SHA256。`ssh_config_apply` 把 expected SHA256、目标内容或单文件 diff、validator 和回滚绑定进审批摘要；执行时重新验证版本，在同目录写入并同步临时文件，保存 `0600` 备份，运行白名单 argv validator，原子 rename，并在后置校验失败时恢复。成功操作写入 `file_operations`，`ssh_config_restore` 只能引用该 ID。

Workspace 根只能来自启动配置。未声明显式列表时，控制面创建启动目录下的 `workspace/` 并注册为 `default/read_write`；可通过启动配置或环境变量改位置，也可显式关闭。受 Cookie/CSRF 保护的管理员 API 可以显示真实根目录、上传、预览和删除文件或目录，但 LLM 的 `workspace_list` 使用独立的安全能力视图，不包含根路径。上传限制为 100 MiB，拒绝敏感路径和覆盖，通过同目录临时文件、`fsync` 与原子 hard-link 提交；预览限制为 1 MiB 并识别二进制内容；Web 删除使用原子重命名将单个文件或完整目录移动到不可浏览的 `.opspilot-trash`，Workspace 根目录不可删除，并保留摘要与审计证据供人工恢复。Workspace 文件到远端只使用 `workspace_file_upload`：审批同时绑定 Workspace ID、相对路径、读取所得 SHA256、目标主机和远端路径，执行前重新解析白名单路径并校验 SHA256，绝对本地路径通过 `json:"-"` 的内部字段传给内置 SFTP transport。每个 Workspace 使用隐藏的受管目标复用 Run/Approval/Audit 状态机；真实根路径不会进入模型请求或输出。

`workspace_shell` 是唯一开放给模型的本地 Shell。管理员在 SQLite 持久化的 System 设置中明确选择 `sandbox`、`host` 或 `disabled`，默认 `sandbox`。提交时解析出的实际后端写入 `ExecRequest.workspace_shell_backend`，和完整脚本、Workspace ID、相对 cwd、环境与超时一起进入加密审批摘要；执行前再次读取设置，后端不一致即拒绝，从而避免审批后切换权限边界。它复用确定性 Policy、Run、Approval 与 Audit，每个请求最低风险固定为 Change，危险脚本仍升级为 Critical。

Sandbox 后端仅在 Linux 使用配置的 Bubblewrap；不存在或 namespace 创建失败时关闭失败，绝不回退到 Host Shell。沙箱新建 user/mount/PID/network namespace、丢弃 capabilities、禁用嵌套 user namespace 和网络，只读挂载 `/usr` 与动态链接库目录，创建独立 `/proc`、`/dev`、`/tmp`，并按 Workspace access 只读或读写挂载到 `/workspace`。预存的 `.env*`、`.ssh`、`.opspilot-*`、`.data`、`master.key` 与 credential 命名路径，以及 socket、FIFO 和 device 等特殊文件，在 mount namespace 内被遮蔽。

Host 后端直接以服务账户执行，拥有宿主机文件系统与网络权限；Unix 选择 Bash，Windows 依次查找 `pwsh.exe` 与 `powershell.exe`。Host 仅允许 `read_write` Workspace，强制每次一次性人工审批，后端同时跳过会话授权查询并拒绝会话级授权创建。两种后端都使用清理后的环境、有界输出、统一脱敏并隐藏 Workspace 宿主根路径。配置中固定的 Workspace validator 仍使用 argv 和固定环境单独执行，不经过 Shell。

目标主机和最多四级跳板链的非秘密连接字段及更新时间组成 `ssh_connection_digest`，与命令一起进入审批和会话授权摘要；批准后修改地址、用户、认证方式、known_hosts 或跳板链会导致执行失败。

内置实现使用 `golang.org/x/crypto/ssh`、`knownhosts` 和 `github.com/pkg/sftp`。密码只作为进程内 AuthMethod；Keyboard Interactive 只回答一次无回显的密码提示。Unix Agent 连接 `SSH_AUTH_SOCK`，Windows Agent 通过 named pipe 连接系统 OpenSSH Agent。Web/CLI 上传的未加密 OpenSSH 格式私钥限制为 1 MiB，使用 AES-256-GCM 写入 `private_key_cipher`，对外只返回 `has_private_key` 并只在内存解析；不接受或保存宿主机私钥路径。ProxyJump 只能引用注册主机，逐跳验证 host key、检测环路并限制最大深度。

内置实现通过未认证握手扫描协商出的 host key，信任时重新扫描并精确比较 SHA256 指纹，再以 `0600` 追加和同步 known_hosts。未知 key 与 key mismatch 均关闭失败。命令和 SFTP 每次建立独立连接，连接/命令取消会关闭完整跳板链；15 秒 keepalive 连续超时会断开。

双后端到内置单后端的升级是显式破坏性迁移。检测到旧 `transport_backend`、`config_alias`、自由格式 `proxy_jump` 或 `identity_file` 列时，Store 会清理旧主机及依赖的 runs、approvals、tasks、file_operations，再删除这些列，不保留运行时兼容分支。

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

HTTP Chat Handler 使用保留 request logger/value、但移除浏览器取消信号的后台 context，并额外施加 30 分钟上限。浏览器断开后只停止 SSE 写入，原 Agent/Tool goroutine 继续等待审批；Runtime 按 session ID 记录 active 状态并拒绝同会话并发运行。Web 刷新后通过 `GET /api/v1/chat/{id}/state` 同步 active 状态和持久化消息，直到原循环完成。活动会话不能删除。该机制覆盖页面刷新和临时网络中断，不承诺跨服务进程重启恢复内存中的 Agent Loop。独立 SSH Task 的元数据与有界输出会持久化；重启时仍处于活动态的旧进程无法重新附着，会被恢复流程明确标记为 `interrupted`。

## Sequential task plans

复杂任务通过 Eino 专用的 `ops_plan_create`、`ops_plan_get` 和 `ops_plan_step_update` 三个强类型 Tool 编排。计划和步骤分别写入 `agent_plans`、`agent_plan_steps`，session ID 只取可信 Go context，模型不能为其他会话读写计划。创建时只允许 2–8 个不重复步骤，第一步自动进入 `in_progress`；Store 在单个 SQLite 事务中只接受当前步骤的 `completed` 或 `blocked` 转移，完成后自动激活下一步，因而数据库层始终最多只有一个进行中步骤。

计划创建与每次状态转移均写入审计。Chat state 同时返回消息、后台运行状态和最新计划，Web 使用同一恢复轮询展示总进度、当前步骤与完成证据。Agent Loop 达到迭代上限不会删除计划；下一条 `continue` 可调用 `ops_plan_get` 继续当前步骤。旧会话或简单会话没有计划时，`ops_plan_get` 返回可恢复的 `found:false`，而不是用 `ErrNotFound` 中止 Eino ToolNode。计划是编排状态而非额外权限，所有 SSH Tool 仍独立通过 Policy、审批和加密审计。

## Audit storage

`runs.request_json`、stdout 和 stderr 的可检索字段均为脱敏视图；对应原文采用 AES-256-GCM 写入 cipher 字段。MCP/Eino 历史工具永远不会返回 cipher 或解密内容。只有本地审批和显式 `audit show --raw` 会解密。

每次运行还会产生独立事件：`command_started`、`approval_requested`、`approval_granted/rejected`、`command_completed/denied`、`task_cancelled` 等。

## Server observability

服务端日志与执行审计是两条独立链路：Audit 是 SQLite 中不可替代的安全证据，Server Logs 用于排查控制面运行状态。应用统一调用标准库 `log/slog`，初始化时通过 MultiHandler 分发到终端、JSONL 轮转文件和进程内环形缓冲区。`GET /api/v1/logs` 只读取环形缓冲区，Web 轮询该接口不会再次写入请求日志，避免自激式增长。

HTTP Middleware 为请求生成 `request_id` 并记录 method、path、status、耗时、响应字节和来源 IP；该 logger 通过 context 传递给 Agent、Policy、Approval 与 SSH 层，因此一次请求的跨层事件可以关联检索。模型输入、reasoning token、HTTP body、命令参数、脚本和远端输出均不进入服务日志，只记录长度、计数、ID 与最终状态。Handler 对包含 password、secret、token、API key、content、stdout/stderr 等名称的属性执行第二层替换。Debug 日志默认关闭，可通过配置或 `OPS_AGENT_LOG_LEVEL=debug` 启用。

## Conversation persistence

每个新对话由后端生成 session ID，用户消息、最终 Assistant 文本和带 `tool_name` 的脱敏工具结果写入 `chat_messages`，Eino checkpoint 使用同一 session ID。Web 恢复历史时重建工具结果卡片。下一轮模型输入按用户消息划分完整 turn；历史工具结果不会伪造成缺少 ToolCall ID 的协议级 Tool Message，而是作为明确标记、仍按不可信数据处理的 Assistant 历史证据。失败或中断 turn 只要已经执行过工具也会恢复，没有任何活动的失败 turn 则排除。查询最多读取最近 500 条模型相关记录，再按最近完整 turn、单条工具结果、单个 turn 和 256 KiB 总字节预算逐层裁剪；reasoning 不回放。每轮只记录消息数、工具证据数、字节数和截断状态，不记录上下文正文。会话索引按最后事件时间排序，标题取第一条用户消息；删除会话会在同一 SQLite 事务中删除消息和对应 checkpoint，执行证据仍保留在独立的 runs 与 audit_events 中。

Runner 在调用工具前通过 Go context 绑定当前 session ID，Service 创建 Run 时只从可信 context 读取该值，模型工具参数不能伪造会话归属。异步 Task 会把该值复制到脱离 HTTP 请求生命周期的后台 context。Audit 页面按 `runs.session_id` 分组；CLI、MCP、HTTP 直调和升级前的历史记录显示在 Direct / Legacy 分组。

## Model provider routing

模型提供商统一映射为 Eino 的 OpenAI-compatible ChatModel，可保存 OpenAI、DeepSeek、Ollama 和自定义兼容端点。API Key 在进入 SQLite 前使用与审计数据相同的 AES-256-GCM 主密钥加密，对外只返回 `has_api_key`。

SQLite 使用部分唯一索引保证最多只有一个 active provider。切换时服务更新 active route，构建新的 ChatModelAgent 与 Runner，再通过互斥锁原子替换运行时指针；已经取得旧 Runner 的请求可以正常结束，新请求使用新配置。没有 active provider 时才回退到 `OPENAI_*` 环境变量。

命令解释 Agent 默认继承 active provider，也可以通过 `system_settings.subagent_model_provider_id` 固定使用任一已保存 provider。显式选择的 provider 不会静默回退，且在解除引用前禁止删除。其业务截止时间来自 `subagent_timeout_seconds`，允许 5–120 秒、默认 30 秒；底层 HTTP 客户端仅增加固定清理余量，避免维护两套相互竞争的超时配置。

模型发现统一请求配置 Base URL 下的 `GET /models`，兼容 OpenAI 标准的 `data[].id`，同时容忍部分实现的 `models[]` 包装。请求最长 15 秒、响应最大 2 MiB，并禁止 HTTP 重定向，避免 Authorization Header 被转发到其他地址；上游错误在返回 Web 前会经过密钥替换和通用脱敏。

所有保存、发现与测试流程复用同一 Base URL 规范化函数：无协议的 loopback、私网 IP、`.local` 与单标签主机补全为 HTTP，公网域名补全为 HTTPS，并移除末尾误填的 `/models` 或 `/chat/completions`。包含凭据、查询参数或 fragment 的 URL 会被拒绝。

模型测试可以使用已保存配置，也可以使用尚未落库的表单配置。后端复用加密 Key 或请求中的临时 Key，通过对应 ChatModel 发送 `Hello`；HTTP 调用成功且 Assistant Content 去除空白后非空才返回 Healthy，空响应与协议错误均视为失败。

## Runtime settings

Web 配置中心把模型提供商、SSH 主机和系统设置收敛到同一入口。`system_settings` 单行表保存 Agent 最大模型迭代数、命令解释开关、独立 provider、请求超时和 Workspace Shell 模式；每次修改都会写入 `system_settings_updated` 审计事件。保存后 Runtime 构建新的 ChatModelAgent/Runner 并原子替换指针，因此新请求立即使用新的循环预算和解释模型路由，已经取得旧 Runner 的执行不会被中断。
