# 密钥与本地配置安全

不要把真实 API 密钥、认证令牌或密码写入源码、示例、日志或提交说明。
本地 `.env`、`.env.*` 和 `audio-agent.json` 已加入 Git 忽略规则，
也不会进入 Docker 构建上下文。仅提交不含真实密钥的 `.example` 模板，
例如 `.env.example`、`.env.production.example`、`audio-agent.json.example`。
忽略规则不会移除已跟踪文件，也不能使已经泄露的密钥失效。

## 提交前检查

只暂存需要提交的文件，然后在仓库根目录执行：

```bash
python3 -m unittest discover -s scripts -p 'test_check_secrets.py' -v
python3 scripts/check_secrets.py
```

检查读取 **Git 暂存区**，拒绝本地密钥配置文件、长 `sk-` API 密钥和 JWT。
即使使用 `git add -f`，或暂存密钥后又修改工作区文件，检查仍会发现对应问题。
输出仅包含文件名、行号和规则名，不输出匹配值。示例文件同样检查密钥内容。
GitHub Actions 会在 push 和 pull request 时执行相同检查。

这是针对已知泄露方式的回归保护，不是完整的密钥审计，也不检查 Git 历史。
它不能覆盖所有密钥格式、短令牌、编码或拆分后的值。CI 在推送后才运行，
不能阻止密钥首次上传；请在提交前运行检查，不要依赖 CI 代替人工审查。

## 已泄露密钥的处理

Issue [#2](https://github.com/guccang/blogclaw/issues/2) 涉及历史文件
`cmd/audio-agent/audio-agent.json`。该文件已随 audio-agent 目录在提交
`d738c859cfc7408b96d0add309d5d6c9b3a00c48` 中删除，但旧提交仍可能包含密钥。
本次防误提交保护不表示旧密钥已被撤销，也不表示历史已被清理。

1. 在 MiniMax 官方控制台撤销泄露密钥，检查异常调用、用量及账单。
2. 同时核对旧配置里的其他供应商凭据和 `auth_token`；对已暴露的有效凭据进行轮换。
3. 仅在部署环境的私密配置或受控的密钥管理服务中更新新值，不要写入仓库。
   当前主分支已移除 audio-agent，不要为了保存新密钥恢复旧配置文件。
4. 如果仍需清理历史，先与协作者确认范围、备份及重新克隆安排，再单独执行历史重写。
   历史清理不能撤回他人已有的克隆、缓存或副本，不能替代撤销密钥。
5. 不要在公开 Issue、PR 或日志里粘贴密钥。仅在撤销与用量核查完成后确认事件处理状态。

不要通过调用供应商 API 来验证公开泄露的密钥是否有效。
