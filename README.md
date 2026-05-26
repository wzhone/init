# Linux 初始化脚本

两套脚本：Rocky Linux / Alpine Linux。在装完系统后配置系统。


## 支持环境

- Rocky Linux 8 - 10
- Alpine Linux 3.20 - 3.23


## 使用方式

Rocky Linux：
```bash
bash <(curl -s https://raw.githubusercontent.com/wzhone/init/master/rocky.sh)
```

Alpine Linux：
```bash
apk add --no-cache bash curl
bash <(curl -s https://raw.githubusercontent.com/wzhone/init/master/alpine.sh)
```


## 功能概览

Rocky 版：
- 基础系统：主机名、代理、时间同步（chrony）、TCP BBR、journald 持久化日志
- 安全加固：SSH 端口/空密码/可选禁 root、Fail2ban、AIDE、自动安全更新
- 开发环境：基础工具包、Zsh + Oh My Zsh + 主题/插件 + FZF
- 审计与可视：Lynis / RKHunter、SSH 主机指纹、执行日志
- 其他：Docker CE、SSH 公钥、用户创建

Alpine 版：
- 基础系统：主机名、edge 仓库、时间同步（chrony）、TCP BBR、时区
- 安全加固：SSH 加固（不改端口）、自动安全更新
- 开发环境：基础工具包
- 可视与记录：SSH 主机指纹、执行日志
- 其他：Docker（OpenRC）、SSH 公钥、用户创建（sudo/wheel）


## 菜单一览

Rocky 版（`rocky.sh`）：
1. 设置代理
2. 修改主机名
3. SELinux（含风险提示）
4. 创建自定义用户
5. SSH（端口、root 登录可选、Fail2ban）
6. 基础软件包
7. Zsh 工具链（Oh My Zsh / 主题 / 插件 / FZF）
8. 时间同步（chrony）
9. TCP BBR
10. 自动安全更新
11. AIDE 文件完整性
12. 安全审计
13. Docker CE
14. SSH 公钥配置
15. SSH 主机密钥指纹
16. journald 持久化日志
17. 查看执行日志
18. 系统预检查

Alpine 版（`alpine.sh`）：
1. 修改主机名
2. 创建自定义用户
3. 配置 SSH
4. 启用 edge 仓库
5. 安装基础软件包
6. 同步系统时间
7. 启用 TCP BBR
8. 设置自动安全更新
9. 安装 Docker
10. 配置 SSH 公钥
11. 显示 SSH 主机密钥指纹
12. 设置系统时区
13. 查看执行日志
14. 系统预检查


## 日志与记录

- Rocky：`~/.local/state/init/rocky-init.log`（日志）、`~/.local/state/init/rocky-init.conf`（执行记录）
- Alpine：`~/.local/state/init/alpine-init.log`（日志）、`~/.local/state/init/.steps/`（执行记录）
- 执行记录仅在菜单项成功结束后写入；失败、跳过或中途终止不会标记为已完成。
- 目录权限默认为 700，日志/记录文件为 600。


## 安全提示

- SSH 禁 root / 禁密码登录前，先准备好公钥和可登录用户，避免断连。
- Rocky 修改 SSH 端口前会尝试放行防火墙/SELinux 端口，失败会中止变更；建议确认 firewalld 可用。
- 禁用 SELinux 会削弱系统安全边界，生产环境慎用。


## 许可证

本项目采用 MIT 许可证（见仓库根目录 `LICENSE`）。
