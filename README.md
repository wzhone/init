# Linux 初始化脚本

两套脚本：`el.sh` 用于 EL / Debian / Ubuntu（systemd），`alpine.sh` 用于 Alpine（OpenRC）。


## 支持环境

每个系列只维护最新和上一代稳定版本；Ubuntu 按 LTS 版本计算。当前范围（2026-09）：

| 系列 | 支持版本 |
| --- | --- |
| RHEL / Rocky / AlmaLinux / Oracle Linux / CentOS Stream | 9、10 |
| Debian | 12、13 |
| Ubuntu LTS | 24.04、26.04 |
| Alpine | 3.23、3.24 |

兼容衍生系统按 `/etc/os-release` 中的基础发行版识别，要求使用相同的包管理器与服务管理器。EL 8 及更早版本不再支持。版本范围与 CI 随新稳定版本发布一起维护。


## 使用方式

EL / Debian / Ubuntu（沿用 `el.sh` 文件名）：
```bash
bash <(curl -s https://raw.githubusercontent.com/wzhone/init/main/el.sh)
```

需要 Bash、curl、sudo 和 systemd；RHEL 需要可用的软件仓库。Debian/Ubuntu 最小安装可先以 root 执行 `apt-get update && apt-get install -y sudo curl`。

Alpine Linux：
```bash
apk add --no-cache bash curl
bash <(curl -s https://raw.githubusercontent.com/wzhone/init/main/alpine.sh)
```


## 功能概览

systemd 版：
- 基础系统：主机名、代理、NTS 时间同步（chrony）、TCP BBR、Swap 文件 / zram、journald 持久化日志
- 安全与维护：SSH 端口迁移、AIDE 定期检查、自动更新（EL 用 dnf-automatic，Debian/Ubuntu 用 unattended-upgrades）
- 开发环境：基础工具包、Zsh + Oh My Zsh + 主题/插件 + FZF
- 审计与可视：Lynis 安全审计、SSH 主机指纹、执行日志
- 其他：Docker CE、SSH 公钥、用户创建

Alpine 版：
- 基础系统：主机名、可选 edge 仓库、时间同步（chrony）、TCP BBR、Swap 文件 / zram、时区
- 安全加固：SSH 加固（不改端口）、稳定分支自动更新
- 开发环境：基础工具包
- 可视与记录：SSH 主机指纹、执行日志
- 其他：Docker（OpenRC）、SSH 公钥、用户创建（sudo/wheel）


## 菜单一览

systemd 版（`el.sh`）：
1. 设置代理
2. 修改主机名
3. SELinux（含风险提示）
4. 创建自定义用户
5. SSH 端口迁移
6. 基础软件包
7. Zsh 工具链（Oh My Zsh / 主题 / 插件 / FZF）
8. NTS 时间同步（chrony）
9. TCP BBR
10. 配置 Swap（文件 / zram）
11. 自动更新
12. AIDE 文件完整性定期检查
13. 安全审计
14. Docker CE
15. SSH 公钥配置
16. SSH 主机密钥指纹
17. journald 持久化日志
18. 查看执行日志
19. 系统检查

Alpine 版（`alpine.sh`）：
1. 修改主机名
2. 创建自定义用户
3. 配置 SSH
4. 启用 edge 仓库
5. 安装基础软件包
6. 同步系统时间
7. 启用 TCP BBR
8. 配置 Swap（文件 / zram）
9. 设置自动更新
10. 安装 Docker
11. 配置 SSH 公钥
12. 显示 SSH 主机密钥指纹
13. 设置系统时区
14. 查看执行日志
15. 系统检查


## AIDE、Swap 与自动更新

- AIDE 仅首次初始化基线；重复配置不会覆盖已有基线。`init-aide-check.timer` 每日按本机时区在 04:00–04:30 执行检查，错过后补跑。差异或错误使 `init-aide-check.service` 进入 failed 状态，系统检查会提示，报告可通过 `journalctl -u init-aide-check.service` 查看。这是本机告警，不包含邮件或远程通知。确认变更后再手动更新基线。
- Swap 可选 `/swapfile` 或 zram，大小以 MiB 输入（1024 MiB = 1 GiB）。磁盘文件默认 4096 MiB，zram 默认物理内存的一半、最多 4096 MiB。zram 以优先级 100 与已有磁盘 Swap 共存；已有 zram 设备时保留原配置。EL 使用 `zram-generator`，Debian/Ubuntu 使用 `systemd-zram-generator`，Alpine 使用 `zram-init`；需要内核支持。
- Alpine 自动更新可指定每日时间（默认本机时区 03:00）。每次运行仅使用 `/etc/apk/repositories` 中当前稳定分支的 main/community 仓库，升级全部符合现有包约束的软件包，不限于安全补丁，不使用 `--available` 强制替换版本。edge 和其他版本仓库不参与；依赖这些仓库的包若无法解析，更新会失败并记录日志，不会静默跨版本升级。
- Alpine 更新保留其他 root cron 任务，旧的 `daily/apk-auto-upgrade` 会移至 `/root` 备份。包变更见 `/var/log/apk.log`，结果写入 syslog（标识 `init-apk-upgrade`）；不会自动重启系统。

## 日志与记录

- systemd 版：`~/.local/state/init/el-init.log`（日志）、`~/.local/state/init/el-init.conf`（执行记录，保留原路径）
- Alpine：`~/.local/state/init/alpine-init.log`（日志）、`~/.local/state/init/.steps/`（执行记录）
- 执行记录仅在菜单项成功结束后写入；失败、跳过或中途终止不会标记为已完成。
- 目录权限默认为 700，日志/记录文件为 600。

## 系统检查

两个脚本的系统检查会合并运行前置检查与状态巡检，包含磁盘、CPU、内存、Swap、关键服务和关键配置状态。


## 安全提示

- 修改 SSH 端口需要运行中的 firewalld，Debian/Ubuntu 也可使用 UFW；若使用 `ssh.socket`，需先切换到 `ssh.service`。外部防火墙或云安全组需自行放行新端口。
- 禁用 SELinux 会削弱系统安全边界，生产环境慎用。

## 验证

```bash
bash -n el.sh && bash -n alpine.sh
shellcheck -x el.sh alpine.sh
python3 tests/check_init.py
```

回归检查在临时目录中模拟系统命令，不修改主机配置。CI 还会在支持的发行版容器中检查系统识别、菜单及巡检；容器检查不替代真实主机的内核 Swap 和服务启动验证。


## 许可证

本项目采用 MIT 许可证（见仓库根目录 `LICENSE`）。
