# Linux 初始化脚本



## 功能概览

- 基础系统：主机名、代理、时间同步（chrony）、TCP BBR
- 安全加固：SSH 加固（自定义端口/禁空密码/可选禁用 root 登录）、Fail2ban、AIDE、自动安全更新
- 开发环境：基础工具包、Zsh + Oh My Zsh + 主题/插件（可选）
- 审计与可视：Lynis/RKHunter、SSH 主机指纹、执行日志


## 支持环境

- Rocky Linux 8 / 9 / 10（需要 `sudo` 权限与网络）
- Alpine Linux 3.15 / 3.16（需要 `sudo` 权限）


## 使用方式

```bash
bash <(curl -s https://raw.githubusercontent.com/wzhone/init/master/rocky.sh)
bash <(curl -s https://raw.githubusercontent.com/wzhone/init/master/alpine.sh)
```



## 菜单一览

1. 设置代理
2. 修改主机名
3. SELinux（含风险提示）
4. SSH（端口、root 登录可选、Fail2ban）
5. 基础软件包
6. Zsh 工具链（Oh My Zsh / 主题 / 插件 / FZF）
7. 时间同步（chrony）
8. TCP BBR
9. 自动安全更新
10. AIDE 文件完整性
11. 安全审计
12. Docker CE
13. SSH 公钥配置
14. SSH 主机密钥指纹
15. 创建自定义用户
16. 查看执行日志
17. 系统预检查



## 日志与隐私

- 日志与执行记录存放于 `/tmp`，仅本地可见；多用户环境建议收紧权限（如 `chmod 600`）。
- 无遥测。启用 Zsh 相关功能时会从 GitHub 拉取资源，请先评估再使用。



## 安全提示

- 禁用 SELinux 会削弱系统安全边界，生产环境慎用。
- 禁止 root 登录前，请确保至少存在一个可登录的普通用户，以免失联。



## 许可证

本项目采用 MIT 许可证（见仓库根目录 `LICENSE`）。
