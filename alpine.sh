#!/bin/bash
# 状态标记说明:
#   [+] 成功 - 操作成功完成
#   [-] 错误 - 操作失败或错误
#   [!] 警告 - 需要注意的情况
#   [*] 信息 - 一般信息提示
#   [~] 进行 - 正在执行的操作
#   [>] 跳过 - 跳过的操作
#   [?] 输入 - 需要用户输入

# 日志和配置文件路径
SCRIPT_USER="${SUDO_USER:-$USER}"
[[ -z "$SCRIPT_USER" ]] && SCRIPT_USER="root"
readonly SCRIPT_USER
USER_HOME="$(getent passwd "$SCRIPT_USER" | cut -d: -f6)"
[[ -z "$USER_HOME" ]] && USER_HOME="$HOME"
[[ -z "$USER_HOME" ]] && USER_HOME="/root"
readonly LOG_DIR="$USER_HOME/.local/state/init"
readonly LOG_FILE="$LOG_DIR/alpine-init.log"
readonly CONFIG_FILE="$LOG_DIR/alpine-init.conf"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR" 2>/dev/null || true
touch "$LOG_FILE" "$CONFIG_FILE"
chmod 600 "$LOG_FILE" "$CONFIG_FILE" 2>/dev/null || true

print_status() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"

    case "$level" in
        "INFO")
            echo -e "${BLUE}[*]${NC} $message"
            echo "$timestamp [INFO] $message" >> "$LOG_FILE"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[+]${NC} $message"
            echo "$timestamp [SUCCESS] $message" >> "$LOG_FILE"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            echo "$timestamp [WARNING] $message" >> "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[-]${NC} $message"
            echo "$timestamp [ERROR] $message" >> "$LOG_FILE"
            ;;
        "PROGRESS")
            echo -e "${CYAN}[~]${NC} $message"
            echo "$timestamp [PROGRESS] $message" >> "$LOG_FILE"
            ;;
        *)
            echo -e "${WHITE}$message${NC}"
            echo "$timestamp [LOG] $message" >> "$LOG_FILE"
            ;;
    esac
}

check_result() {
    local code=$1
    local msg_ok="$2"
    local msg_fail="$3"
    if [[ $code -eq 0 ]]; then
        print_status "SUCCESS" "$msg_ok"
        return 0
    else
        print_status "ERROR" "$msg_fail"
        return 1
    fi
}

# 记录某个步骤执行时间（保持原风格）
record_execution() {
    local step="$1"
    local name="$2"
    local now
    now="$(date '+%Y-%m-%d %H:%M:%S')"
    mkdir -p "$LOG_DIR/.steps"
    echo "$now|$name" > "$LOG_DIR/.steps/$step"
}

is_executed() {
    local step="$1"
    [[ -f "$LOG_DIR/.steps/$step" ]]
}

get_execution_time() {
    local step="$1"
    if [[ -f "$LOG_DIR/.steps/$step" ]]; then
        awk -F'|' '{print "[于 "$1" 执行]"}' "$LOG_DIR/.steps/$step"
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "需要 root 权限运行"
        exit 1
    fi
}

ensure_openrc() {
    if ! command -v rc-service >/dev/null 2>&1; then
        print_status "ERROR" "未检测到 OpenRC（rc-service）。请确认这是一个完整的 Alpine Linux 系统（非精简容器），并安装/启用 openrc 后再运行。"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_status "ERROR" "缺少 /etc/os-release，无法确认系统。"
        exit 1
    fi
    . /etc/os-release
    if [[ "$ID" != "alpine" ]]; then
        print_status "ERROR" "当前系统不是 Alpine Linux（检测到: $PRETTY_NAME）。"
        exit 1
    fi
    print_status "SUCCESS" "检测到 Alpine Linux：$PRETTY_NAME"
}

# ========== 1) 修改主机名 ==========
change_hostname() {
    record_execution "1" "修改主机名"
    print_status "PROGRESS" "当前主机名: $(hostname)"
    read -rp "[?] 输入新主机名（留空取消）: " NEW_HOSTNAME
    if [[ -z "$NEW_HOSTNAME" ]]; then
        print_status "WARNING" "未输入，已跳过"
        return 0
    fi

    echo "$NEW_HOSTNAME" > /etc/hostname
    hostname "$NEW_HOSTNAME"
    if command -v rc-service >/dev/null 2>&1; then
        rc-service hostname restart >/dev/null 2>&1
    fi
    check_result $? "主机名已更新为 $NEW_HOSTNAME" "主机名更新失败"
}

# ========== 2) 配置 SSH==========
configure_ssh() {
    record_execution "2" "配置 SSH"

    local SSHD_CFG="/etc/ssh/sshd_config"

    # 设置/追加配置项的安全助手：就地修改，不覆盖整文件
    _set_sshd_option() {
        local key="$1"; shift
        local val="$*"
        if grep -qiE "^[#[:space:]]*${key}[[:space:]]" "$SSHD_CFG"; then
            # 就地替换同名项（不区分大小写）
            sed -i "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$SSHD_CFG"
        else
            printf '%s %s\n' "$key" "$val" >>"$SSHD_CFG"
        fi
    }

    # 一些通用的、不会导致锁死的默认优化：保持端口不变，不改 root/password 行为
    _set_sshd_option "X11Forwarding" "no"
    _set_sshd_option "AllowTcpForwarding" "yes"
    _set_sshd_option "ClientAliveInterval" "120"
    _set_sshd_option "ClientAliveCountMax" "2"

    # 诊断：是否存在非 root 的可登录用户，以及是否已有 SSH 公钥
    _has_nonroot_user() {
        awk -F: '$3>=1000 && $7!="/sbin/nologin" && $7!="/bin/false"{print $1}' /etc/passwd | grep -q .
    }
    _any_authorized_key() {
        # 检测 /root 和 /home/* 下 authorized_keys 是否存在且非空
        find /root /home -maxdepth 3 -type f -name authorized_keys -size +0c -print -quit 2>/dev/null | grep -q .
    }

    local will_disable_root="yes"
    local will_disable_pw="yes"

    # 风险提示：若禁用 root 登录与口令登录，而系统没有可用的公钥/第二用户，会有锁死风险
    if ! _any_authorized_key || ! _has_nonroot_user; then
        print_status "WARNING" "即将进行 SSH 加固：禁止 root 登录、禁止口令登录。"
        if ! _any_authorized_key; then
            print_status "WARNING" "未发现任何 authorized_keys，禁用口令登录将可能导致无法登录！"
        fi
        if ! _has_nonroot_user; then
            print_status "WARNING" "未发现非 root 可登录用户，禁用 root 登录将可能导致无法登录！"
        fi
        echo
        read -r -p "[?] 是否仍要应用上述两项加固？输入 y 继续，n 跳过（仅应用其它安全项） [y/N]: " ans
        case "$ans" in
            y|Y) : ;;
            *)
                will_disable_root="no"
                will_disable_pw="no"
                print_status "INFO" "已跳过『禁止 root 登录/禁止口令登录』，你可以稍后手动配置。"
                ;;
        esac
    fi

    # 应用加固（若未被用户跳过）
    if [[ "$will_disable_root" == "yes" ]]; then
        _set_sshd_option "PermitRootLogin" "no"
    else
        # 若用户跳过，则尽量使用更安全的缺省（至少禁止 root 密码登录）
        _set_sshd_option "PermitRootLogin" "prohibit-password"
    fi
    if [[ "$will_disable_pw" == "yes" ]]; then
        _set_sshd_option "PasswordAuthentication" "no"
        _set_sshd_option "ChallengeResponseAuthentication" "no"
        # Alpine 默认未启用 PAM，这里明确为 no
        _set_sshd_option "UsePAM" "no"
    fi

    # 启用并重启
    rc-update add sshd >/dev/null 2>&1 || true
    if command -v rc-service >/dev/null 2>&1; then
        rc-service sshd restart >/dev/null 2>&1
    elif command -v service >/dev/null 2>&1; then
        service sshd restart >/dev/null 2>&1
    else
        /etc/init.d/sshd restart >/dev/null 2>&1 || true
    fi
    check_result $? "OpenSSH 已启用（按你的选择完成加固）" "OpenSSH 启动失败"

    print_status "INFO" "如需更改 SSH 端口或其它选项，请编辑 $SSHD_CFG 后重启：rc-service sshd restart"
}

# ========== 3) 安装基础软件包 ==========
install_basic_packages() {
    record_execution "3" "安装基础软件包"
    print_status "PROGRESS" "更新索引并升级系统"
    apk update && apk upgrade --available

    local pkgs=(
        bash sudo curl wget ca-certificates tzdata
        git vim nano htop tmux tree unzip zip p7zip rsync
        bind-tools busybox-extras net-tools iproute2 lsof coreutils util-linux
        chrony chrony-openrc
    )
    apk add --no-cache "${pkgs[@]}"
    check_result $? "基础软件包安装完成" "基础软件包安装失败"

    # 启用 crond（BusyBox 自带或 dcron）
    if ! rc-status | grep -q crond; then
        rc-update add crond >/dev/null 2>&1 || true
        rc-service crond start >/dev/null 2>&1 || true
    fi
}

# ========== 4) 安装 ZSH 工具链 ==========
install_zsh_tools() {
    record_execution "4" "安装 ZSH 工具链"
    print_status "PROGRESS" "安装 ZSH/插件，并为当前用户准备 Oh My Zsh（非强制）"

    apk add --no-cache zsh zsh-autosuggestions zsh-syntax-highlighting fzf git curl >/dev/null 2>&1

    local TARGET_USER="${SUDO_USER:-$USER}"
    if [[ -z "$TARGET_USER" ]]; then TARGET_USER="root"; fi

    # 安装 oh-my-zsh（静默忽略失败）
    su - "$TARGET_USER" -c "sh -c \"\$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\" \"\" --unattended" >/dev/null 2>&1 || true

    # 默认使用 /bin/zsh 作为 shell（BusyBox adduser 支持 -s；对于现有用户可用 chsh 或直接修改 /etc/passwd）
    if command -v chsh >/dev/null 2>&1; then
        chsh -s /bin/zsh "$TARGET_USER" >/dev/null 2>&1 || true
    else
        # 若无 chsh，尝试直接替换 /etc/passwd（保守做法）
        sed -i "s#^\(${TARGET_USER}:[^:]*:[0-9]*:[0-9]*:[^:]*:[^:]*:\).*#\1/bin/zsh#" /etc/passwd 2>/dev/null || true
    fi

    print_status "SUCCESS" "ZSH 工具链安装完成（用户: $TARGET_USER）"
}

# ========== 5) 同步系统时间 ==========
sync_system_time() {
    record_execution "5" "同步系统时间"
    print_status "PROGRESS" "配置 Chrony（chronyd）为 NTP 客户端"
    apk add --no-cache chrony chrony-openrc >/dev/null 2>&1 || true
    if [[ -f /etc/chrony/chrony.conf ]]; then
        cp -a /etc/chrony/chrony.conf "/etc/chrony/chrony.conf.bak.$(date +%Y%m%d%H%M%S)"
        sed -i 's/^#\?pool .*/pool pool.ntp.org iburst/' /etc/chrony/chrony.conf
    fi
    rc-update add chronyd >/dev/null 2>&1
    rc-service chronyd restart >/dev/null 2>&1
    check_result $? "Chrony 已启动" "Chrony 启动失败"
}

# ========== 6) 启用 TCP BBR ==========
enable_bbr() {
    record_execution "6" "启用 TCP BBR"
    print_status "PROGRESS" "写入 /etc/sysctl.conf 并加载"
    cp -a /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    cat >>/etc/sysctl.conf <<'EOF'

# ---- added by alpine-init.sh ----
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl -p >/dev/null 2>&1
    check_result $? "BBR 已尝试启用（需内核支持）" "sysctl 加载失败"
}

# ========== 7) 设置自动安全更新 ==========
setup_auto_updates() {
    record_execution "7" "设置自动安全更新"
    print_status "PROGRESS" "创建 /etc/periodic/daily/apk-auto-upgrade 并启用 crond"
    cat >/etc/periodic/daily/apk-auto-upgrade <<'EOF'
#!/bin/sh
apk -U update
apk upgrade --available
EOF
    chmod +x /etc/periodic/daily/apk-auto-upgrade
    rc-update add crond >/dev/null 2>&1 || true
    rc-service crond start >/dev/null 2>&1 || true
    print_status "SUCCESS" "已启用每日自动升级（crond + /etc/periodic/daily）"
}

# ========== 8) 配置 AIDE ==========
configure_aide() {
    record_execution "8" "配置 AIDE"
    print_status "PROGRESS" "安装 AIDE（如当前分支无包会失败并提示）"
    if apk add --no-cache aide >/dev/null 2>&1; then
        print_status "SUCCESS" "AIDE 已安装，可使用 'aide --init' 初始化数据库"
    else
        print_status "WARNING" "当前仓库未提供 AIDE 或安装失败（edge/testing 才有时）。请手动启用可用仓库后重试。"
        return 0
    fi
}

# ========== 9) 系统安全审计 ==========
security_audit() {
    record_execution "9" "系统安全审计"
    print_status "PROGRESS" "安装 Lynis 并执行审计（若安装失败会提示）"
    if apk add --no-cache lynis >/dev/null 2>&1; then
        lynis audit system || true
        print_status "SUCCESS" "Lynis 审计已运行（输出见终端或日志）"
    else
        print_status "WARNING" "当前仓库未提供 Lynis 或安装失败（edge/testing 才有时）。请手动启用可用仓库后重试。"
    fi
}

# ========== 10) 安装 Docker==========
install_docker() {
    record_execution "10" "安装 Docker"
    print_status "PROGRESS" "安装并启用 Docker（OpenRC）"
    apk add --no-cache docker >/dev/null 2>&1
    # 确保 cgroups 服务启用（Alpine 3.19+ 多为 unified）
    rc-update add cgroups >/dev/null 2>&1 || true
    rc-service cgroups start >/dev/null 2>&1 || true
    rc-update add docker boot >/dev/null 2>&1
    rc-service docker start >/dev/null 2>&1
    check_result $? "Docker 已安装并启动" "Docker 启动失败"

    # 将当前（或 sudo 调用者）加入 docker 组
    addgroup -S docker >/dev/null 2>&1 || true
    local TARGET_USER="${SUDO_USER:-$USER}"
    if [[ -n "$TARGET_USER" ]]; then
        addgroup "$TARGET_USER" docker >/dev/null 2>&1 || true
    fi
}

# ========== 11) 配置 SSH 公钥 ==========
configure_ssh_keys() {
    record_execution "11" "配置 SSH 公钥"
    local TARGET_USER
    read -rp "[?] 目标用户（默认当前用户 $SUDO_USER/$USER）: " TARGET_USER
    [[ -z "$TARGET_USER" ]] && TARGET_USER="${SUDO_USER:-$USER}"
    [[ -z "$TARGET_USER" ]] && TARGET_USER="root"
    local HOME_DIR
    HOME_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
    [[ -z "$HOME_DIR" ]] && HOME_DIR="/home/$TARGET_USER"

    mkdir -p "$HOME_DIR/.ssh"
    chmod 700 "$HOME_DIR/.ssh"
    touch "$HOME_DIR/.ssh/authorized_keys"
    chmod 600 "$HOME_DIR/.ssh/authorized_keys"
    chown -R "$TARGET_USER":"$TARGET_USER" "$HOME_DIR/.ssh"

    print_status "INFO" "请粘贴公钥（以 ssh-ed25519/ssh-rsa 开头），结束后 Ctrl+D："
    cat >> "$HOME_DIR/.ssh/authorized_keys"
    print_status "SUCCESS" "已写入 $HOME_DIR/.ssh/authorized_keys"
}

# ========== 12) 显示 SSH 主机密钥指纹 ==========
show_ssh_fingerprints() {
    record_execution "12" "显示 SSH 主机密钥指纹"
    print_status "INFO" "ECDSA:"
    ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null || true
    print_status "INFO" "ED25519:"
    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || true
    print_status "INFO" "RSA:"
    ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null || true
}

# ========== 13) 创建自定义用户 ==========
create_custom_user() {
    record_execution "13" "创建自定义用户"
    local NEW_USER
    read -rp "[?] 输入新用户名: " NEW_USER
    if [[ -z "$NEW_USER" ]]; then
        print_status "WARNING" "未输入用户名，已跳过"
        return 0
    fi

    # 可选 shell，默认 /bin/ash；若已安装 zsh，可选 zsh
    local DEFAULT_SHELL="/bin/ash"
    if command -v zsh >/dev/null 2>&1; then
        DEFAULT_SHELL="/bin/zsh"
    fi
    read -rp "[?] 登录 shell（默认 $DEFAULT_SHELL）: " USER_SHELL
    [[ -z "$USER_SHELL" ]] && USER_SHELL="$DEFAULT_SHELL"

    # 创建用户与家目录（BusyBox adduser 支持 -s 指定 shell）
    adduser -s "$USER_SHELL" "$NEW_USER"
    check_result $? "用户 $NEW_USER 已创建（shell: $USER_SHELL）" "创建用户失败" || return 1

    print_status "INFO" "为 $NEW_USER 设置密码："
    passwd "$NEW_USER"

    # 安装 sudo 并启用 wheel 组免注释规则
    apk add --no-cache sudo >/dev/null 2>&1 || true
    addgroup -S wheel >/dev/null 2>&1 || true
    addgroup "$NEW_USER" wheel >/dev/null 2>&1 || true
    if grep -qE '^\s*#\s*%wheel\s+ALL=\(ALL\)\s+ALL' /etc/sudoers; then
        cp -a /etc/sudoers "/etc/sudoers.bak.$(date +%Y%m%d%H%M%S)"
        sed -i 's|^\s*#\s*%wheel\s\+ALL=(ALL)\s\+ALL|%wheel ALL=(ALL) ALL|' /etc/sudoers
    fi

    print_status "SUCCESS" "已将 $NEW_USER 加入 wheel 组并启用 sudo"
}

# ========== 14) 查看执行日志 ==========
view_logs() {
    record_execution "14" "查看执行日志"
    if [[ -s "$LOG_FILE" ]]; then
        print_status "INFO" "日志文件: $LOG_FILE"
        tail -n 200 "$LOG_FILE"
    else
        print_status "WARNING" "日志文件为空: $LOG_FILE"
    fi
}

# ========== 15) 系统预检查 ==========
pre_check() {
    record_execution "15" "系统预检查"
    check_os
    ensure_openrc

    print_status "PROGRESS" "检查网络连通性（ping dl-cdn.alpinelinux.org）"
    if ping -c 1 -W 2 dl-cdn.alpinelinux.org >/dev/null 2>&1; then
        print_status "SUCCESS" "网络连通正常"
    else
        print_status "WARNING" "无法连通 dl-cdn.alpinelinux.org，后续安装可能失败"
    fi

    print_status "PROGRESS" "检查磁盘剩余空间"
    local avail_kb
    avail_kb=$(df --output=avail / | tail -1 | tr -d ' ' 2>/dev/null)
    if [[ -z "$avail_kb" || ! "$avail_kb" =~ ^[0-9]+$ ]]; then
        print_status "WARNING" "无法准确获取磁盘剩余空间"
    else
        local avail_gb=$((avail_kb / 1024 / 1024))
        if [[ $avail_kb -lt 1048576 ]]; then
            print_status "WARNING" "硬盘剩余空间不足 1GB (当前: ${avail_gb}GB)"
        else
            print_status "SUCCESS" "硬盘剩余空间约 ${avail_gb}GB"
        fi
    fi
}

show_menu() {
    clear
    echo -e "${WHITE}==================================${NC}"
    echo -e "${WHITE}  Alpine Linux 系统初始化脚本  ${NC}"
    echo -e "${WHITE}==================================${NC}"

    local menu_items=(
        "修改主机名"
        "配置 SSH"
        "安装基础软件包"
        "安装 ZSH 工具链"
        "同步系统时间"
        "启用 TCP BBR"
        "设置自动安全更新"
        "配置 AIDE"
        "系统安全审计（Lynis）"
        "安装 Docker"
        "配置 SSH 公钥"
        "显示 SSH 主机密钥指纹"
        "创建自定义用户（含 sudo/wheel）"
    )

    for i in $(seq 1 ${#menu_items[@]}); do
        if is_executed "$i"; then
            local exec_time
            exec_time=$(get_execution_time "$i" | cut -c 2-20)
            printf "${GREEN}%2d. %-38s ✓ %s${NC}\n" "$i" "${menu_items[$((i-1))]}" "$exec_time"
        else
            printf "%2d. %-38s\n" "$i" "${menu_items[$((i-1))]}"
        fi
    done

    echo -e "\n14. 查看执行日志"
    echo "15. 系统预检查"
    echo "0.  退出"
    echo -e "${WHITE}==================================${NC}"
    echo -e "${CYAN}日志文件: $LOG_FILE${NC}"
    echo -e "${WHITE}==================================${NC}"
}

main() {
    require_root
    check_os
    ensure_openrc

    while true; do
        show_menu
        read -rp "请输入序号 (0-15): " choice
        case "$choice" in
            1) change_hostname ;;
            2) configure_ssh ;;
            3) install_basic_packages ;;
            4) install_zsh_tools ;;
            5) sync_system_time ;;
            6) enable_bbr ;;
            7) setup_auto_updates ;;
            8) configure_aide ;;
            9) security_audit ;;
            10) install_docker ;;
            11) configure_ssh_keys ;;
            12) show_ssh_fingerprints ;;
            13) create_custom_user ;;
            14) view_logs ;;
            15) pre_check ;;
            0)
                print_status "INFO" "用户退出脚本"
                echo -e "${GREEN}[+] 感谢使用！${NC}"
                exit 0
                ;;
            *)
                print_status "WARNING" "无效选择，请输入 0-15"
                sleep 1
                ;;
        esac
    done
}

# 允许通过参数直接调用某个步骤函数： ./init-alpine.sh install_basic_packages
if [[ $# -gt 0 ]]; then
    "$@"
else
    main
fi
