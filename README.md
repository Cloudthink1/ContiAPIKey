# Codex APDU 独立网关

Windows 实验工程。原版 Codex CLI 通过自定义模型提供商连接本机网关。网关进程负责 HTTP/SSE、浏览器回调和 APDU 调度，模拟芯片处理上游身份验证、凭据和 TLS。每个网关进程绑定一个服务模式、账号别名和初始模型。本地凭据助手由 Codex 的 `auth.command` 调用，输出短期网关令牌。

```text
Codex ── HTTP/SSE ── 本机网关 ── APDU ── 软件芯片
      └─ 凭据助手 ── /session                │
                          主机转发 TLS 密文 ──┴─ 上游
```

## 构建与离线演示

需要 PowerShell 7、Rust 1.93.0 和 Windows C++ 工具链。实际联调及原生 TLS 测试还需要 CMake。本机构建可使用项目缓存和已安装的工具链。首次在其他电脑构建会下载公开依赖。

在本目录运行以下命令。`-Offline` 使用已有依赖缓存，首次没有缓存时去掉该参数。

```powershell
pwsh -File .\build.ps1 -Offline -Native -Test
pwsh -File .\run.ps1
```

启动菜单提供 ChatGPT 和 DeepSeek 的真实服务与离线演示。ChatGPT 需要授权时会先打开官方登录页。运行中的会话绑定所选服务，退出后可重新启动并选择另一种。脚本和自动化可以用 `-Mode` 跳过菜单，并用 `-Live` 连接真实服务。

离线演示可用 `/model` 切换模型名，所有模型名使用同一个本地固定响应。ChatGPT 真实模式可切换到当前账号目录提供的模型。真实 DeepSeek 适配器当前支持 `deepseek-flash`，选择其他模型会返回可用模型提示。

在 Windows PowerShell 中找不到 `pwsh` 时，运行 `& '.\start.cmd'`。启动器会查找已安装的 PowerShell 7 或 Codex 自带的运行环境。

默认从 `PATH` 查找官方 Codex CLI，也可用 `-CodexExe` 指定路径。每次启动生成独立的 Codex 会话目录，程序退出后关闭网关并撤销本次本机授权。离线模式使用本机固定模型回复和测试证书。离线请求记录含本次演示的提示词与回复，保存在 `.runtime/runs`。

```powershell
pwsh -File .\run.ps1 -Mode chatgpt -Verify
pwsh -File .\run.ps1 -Mode deepseek -Verify
pwsh -File .\run.ps1 -VerifyTools
```

`-Verify` 检查原版 Codex 的两轮上下文、长 UTF-8 提示词和日志。`-VerifyTools` 用本机模型触发一个已注册的 Codex 函数，检查工具结果是否沿同一链路送回。原生芯片测试另用本机 TLS 服务验证上游 OAuth 兑换、刷新和令牌边界。

## 真实模式

真实模式会将所发提示词交给所选服务商，可能产生费用或消耗额度。`-Verify -Live` 只发送两条内置测试提示词。每个模式的凭据保存在 `.runtime/profiles` 的独立目录，由软件芯片使用当前 Windows 账户的 DPAPI 保护。同一 Windows 账户下有权访问该目录并运行芯片的进程可以使用已保存的凭据。

- **DeepSeek**。先用 `key-add` 将已有 Key 文件导入新项目的指定别名。Key 文件路径可以使用绝对路径。

  ```powershell
  .\target\debug\codex-apdu.exe key-add "$PWD\.runtime\profiles\DeepSeek" default "E:\path\to\key.txt"
  pwsh -File .\run.ps1 -Mode deepseek -Live -Alias default
  ```

- **ChatGPT**。先选择别名。首次启动时浏览器打开官方授权页，之后复用该别名的片内凭据。网关默认选取账号模型目录里优先级最高的可见模型，也可用 `-Model` 指定。

  ```powershell
  pwsh -File .\run.ps1 -Mode chatgpt -Live -Alias default
  ```

真实模式支持文本和标准 `function` 工具请求。图片、自定义工具格式和上下文压缩端点需要额外适配。模拟芯片与网关共用同一台 Windows 主机，同账户进程可能访问其内存和 DPAPI 数据。实体芯片是验证硬件隔离的下一阶段。

## 与直连版本对照

| 项目 | 既有直连版本 | 独立网关版本 |
|---|---|---|
| Codex 接入 | 改造版 Codex 调度 APDU | 原版 Codex 通过配置发送 HTTP/SSE |
| 登录编排 | 改造版 Codex 启动浏览器并接收回调 | 网关收到凭据助手请求后调度浏览器和回调 |
| PKCE、上游令牌 | 模拟芯片生成 verifier 和 state，兑换并刷新上游令牌 | 同样在模拟芯片中处理，原版 Codex 持有独立网关令牌 |
| TLS | 模拟芯片验证上游证书，主机转发密文 | 模拟芯片验证上游证书，主机转发密文 |
| 凭据保存 | 旧项目各模式配置目录 | 新项目 `.runtime/profiles` |

网关提供 `/session` 和 `/v1/responses`。前者使用每次启动随机生成的本机引导凭据，后者使用网关签发的短期令牌。ChatGPT 的 APDU 登录沿用 `71`、`73`、`74`。浏览器收到 chip 生成的 challenge 和 state，回调只返回授权码和 state，`code_verifier` 用于芯片内的兑换请求。上游 OAuth 和模型 TLS 的目标由芯片及其转发白名单约束。
