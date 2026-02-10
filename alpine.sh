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
        print_status "ERROR" "未检测到 OpenRC（rc-service）。请确认这是一个完整的 Alpine Linux 系统（非精简容器）。"
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

ensure_apk_repo() {
    local repo_line="$1"
    local repo_url
    repo_url="$(repo_url_from_line "$repo_line")"
    if [[ -z "$repo_url" ]]; then
        print_status "ERROR" "无法解析仓库地址：$repo_line"
        return 1
    fi
    if ! repo_index_reachable "$repo_url"; then
        print_status "WARNING" "仓库不可用，已跳过：$repo_line"
        return 1
    fi
    if grep -Fxq "$repo_line" /etc/apk/repositories 2>/dev/null; then
        print_status "INFO" "仓库已存在：$repo_line"
    else
        echo "$repo_line" >> /etc/apk/repositories
        print_status "SUCCESS" "已添加仓库：$repo_line"
    fi
    return 0
}

repo_url_from_line() {
    local repo_line="$1"
    local first second
    first="$(echo "$repo_line" | awk '{print $1}')"
    second="$(echo "$repo_line" | awk '{print $2}')"
    if [[ "$first" == @* && -n "$second" ]]; then
        echo "$second"
        return 0
    fi
    if [[ "$first" =~ ^https?:// ]]; then
        echo "$first"
        return 0
    fi
    return 1
}

repo_index_reachable() {
    local repo_url="$1"
    local arch=""
    local idx_url
    repo_url="${repo_url%/}"
    if command -v apk >/dev/null 2>&1; then
        arch="$(apk --print-arch 2>/dev/null || true)"
    fi

    # Alpine 仓库通常为 <repo>/<arch>/APKINDEX.tar.gz；兼容同时探测两种路径
    for idx_url in \
        "${repo_url}/APKINDEX.tar.gz" \
        "${repo_url}/${arch}/APKINDEX.tar.gz"
    do
        [[ "$idx_url" =~ //APKINDEX\.tar\.gz$ ]] && continue
        if command -v wget >/dev/null 2>&1 && wget -q --spider "$idx_url" >/dev/null 2>&1; then
            return 0
        fi
        if command -v curl >/dev/null 2>&1 && curl -fsSI --connect-timeout 5 "$idx_url" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

ensure_wheel_sudoers() {
    local sudoers_backup
    sudoers_backup="/etc/sudoers.bak.$(date +%Y%m%d%H%M%S)"
    cp -a /etc/sudoers "$sudoers_backup" 2>/dev/null || true

    if grep -qE '^[[:space:]]*#?[[:space:]]*%wheel[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+NOPASSWD:[[:space:]]+ALL' /etc/sudoers; then
        sed -i -E 's|^[[:space:]]*#?[[:space:]]*%wheel[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+NOPASSWD:[[:space:]]+ALL|%wheel ALL=(ALL:ALL) NOPASSWD: ALL|' /etc/sudoers
    elif grep -qE '^[[:space:]]*#?[[:space:]]*%wheel[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL' /etc/sudoers; then
        sed -i -E 's|^[[:space:]]*#?[[:space:]]*%wheel[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL|%wheel ALL=(ALL:ALL) NOPASSWD: ALL|' /etc/sudoers
    else
        if ! grep -qE '^[[:space:]]*([#@]includedir)[[:space:]]+/etc/sudoers\.d' /etc/sudoers; then
            echo "#includedir /etc/sudoers.d" >> /etc/sudoers
        fi
        mkdir -p /etc/sudoers.d
        cat > /etc/sudoers.d/10-wheel <<'EOF'
%wheel ALL=(ALL:ALL) NOPASSWD: ALL
EOF
        chmod 440 /etc/sudoers.d/10-wheel
    fi

    if command -v visudo >/dev/null 2>&1; then
        if ! visudo -cf /etc/sudoers >/dev/null 2>&1; then
            [[ -f "$sudoers_backup" ]] && cp -a "$sudoers_backup" /etc/sudoers
            rm -f /etc/sudoers.d/10-wheel
            print_status "ERROR" "sudoers 配置校验失败，已回滚"
            return 1
        fi
    fi
    return 0
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
    local SSHD_BAK
    SSHD_BAK="${SSHD_CFG}.bak.$(date +%Y%m%d%H%M%S)"
    local will_disable_root="yes"
    local will_disable_pw="yes"
    local ans
    local has_key="no"
    local has_nonroot="no"

    # 设置/追加配置项工具方法
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

    # 是否存在非 root 的可登录用户，以及是否已有 SSH 公钥
    _has_nonroot_user() {
        awk -F: '$3>=1000 && $7!="/sbin/nologin" && $7!="/bin/false"{print $1}' /etc/passwd | grep -q .
    }
    _any_authorized_key() {
        # 检测 /root 和 /home/* 下 authorized_keys 是否存在且非空
        find /root /home -maxdepth 3 -type f -name authorized_keys -size +0c -print -quit 2>/dev/null | grep -q .
    }
    _restart_sshd() {
        if command -v rc-service >/dev/null 2>&1; then
            rc-service sshd restart >/dev/null 2>&1
        elif command -v service >/dev/null 2>&1; then
            service sshd restart >/dev/null 2>&1
        else
            /etc/init.d/sshd restart >/dev/null 2>&1
        fi
    }

    _any_authorized_key && has_key="yes"
    _has_nonroot_user && has_nonroot="yes"

    # 风险提示：避免把自己锁在外面
    print_status "WARNING" "变更后请先开新终端测试 SSH 登录成功，再退出当前会话。"
    print_status "INFO" "当前检测：authorized_keys=$has_key, 非 root 可登录用户=$has_nonroot"

    read -r -p "[?] 输入 YES 才继续执行 SSH 配置: " ans
    if [[ "$ans" != "YES" ]]; then
        print_status "WARNING" "已取消 SSH 配置"
        return 0
    fi

    cp -a "$SSHD_CFG" "$SSHD_BAK" 2>/dev/null || true
    print_status "INFO" "已备份 SSH 配置: $SSHD_BAK"

    # 通用优化
    _set_sshd_option "X11Forwarding" "no"
    _set_sshd_option "AllowTcpForwarding" "yes"
    _set_sshd_option "ClientAliveInterval" "60"
    _set_sshd_option "ClientAliveCountMax" "3"

    # 高风险项：禁用 root 登录与口令登录
    if [[ "$has_key" != "yes" || "$has_nonroot" != "yes" ]]; then
        print_status "ERROR" "检测到高风险条件："
        if [[ "$has_key" != "yes" ]]; then
            print_status "ERROR" "未发现任何 authorized_keys，禁用口令登录可能直接失联。"
        fi
        if [[ "$has_nonroot" != "yes" ]]; then
            print_status "ERROR" "未发现非 root 可登录用户，禁用 root 登录可能直接失联。"
        fi
        read -r -p "[?] 若仍要禁用 root/密码登录，请输入 LOCKOUT_RISK；其它输入将跳过该高风险项: " ans
        if [[ "$ans" != "LOCKOUT_RISK" ]]; then
            will_disable_root="no"
            will_disable_pw="no"
            print_status "WARNING" "已自动跳过『禁用 root 登录/禁用口令登录』。"
        fi
    else
        read -r -p "[?] 是否执行高强度加固（禁用 root 登录 + 禁用口令登录）[y/N]: " ans
        case "$ans" in
            y|Y) : ;;
            *)
                will_disable_root="no"
                will_disable_pw="no"
                print_status "INFO" "已跳过高强度加固，仅应用通用安全项。"
                ;;
        esac
    fi

    # 应用加固（若未被跳过）
    if [[ "$will_disable_root" == "yes" ]]; then
        _set_sshd_option "PermitRootLogin" "no"
    fi
    if [[ "$will_disable_pw" == "yes" ]]; then
        _set_sshd_option "PasswordAuthentication" "no"
        _set_sshd_option "ChallengeResponseAuthentication" "no"
    fi

    # 语法检查失败则回滚
    if command -v sshd >/dev/null 2>&1; then
        if ! sshd -t -f "$SSHD_CFG" >/dev/null 2>&1; then
            print_status "ERROR" "sshd 配置语法检查失败，已回滚到备份配置。"
            [[ -f "$SSHD_BAK" ]] && cp -a "$SSHD_BAK" "$SSHD_CFG"
            return 1
        fi
    fi

    # 启用并重启，失败时尝试回滚
    rc-update add sshd >/dev/null 2>&1 || true
    if _restart_sshd; then
        print_status "SUCCESS" "OpenSSH 已启用"
    else
        print_status "ERROR" "OpenSSH 启动失败，正在尝试回滚配置。"
        [[ -f "$SSHD_BAK" ]] && cp -a "$SSHD_BAK" "$SSHD_CFG"
        if _restart_sshd; then
            print_status "WARNING" "已回滚并恢复 sshd，请检查配置后重试。"
        else
            print_status "ERROR" "回滚后 sshd 仍启动失败，请立刻在控制台修复。"
        fi
        return 1
    fi

    print_status "WARNING" "不要立即退出当前会话，请先新开终端验证 SSH 登录是否正常。"
    print_status "INFO" "如需更改SSH端口或其它选项，编辑 $SSHD_CFG 后执行 rc-service sshd restart"
}

# ========== 3) 启用 edge 仓库 ==========
setup_edge_repo() {
    record_execution "3" "启用 edge 仓库"
    local edge_testing_repo="@edge_testing https://dl-cdn.alpinelinux.org/alpine/edge/testing"
    if ! ensure_apk_repo "$edge_testing_repo"; then
        return 1
    fi
    if apk update >/dev/null 2>&1; then
        print_status "SUCCESS" "APK 仓库索引已刷新"
    else
        print_status "ERROR" "APK 索引刷新失败，下面输出详细错误："
        apk update || true
        return 1
    fi
}

# ========== 4) 安装基础软件包 ==========
install_basic_packages() {
    record_execution "4" "安装基础软件包"
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
    print_status "PROGRESS" "尝试启用 TCP BBR..."

    local bbr_conf_file="/etc/sysctl.d/99-bbr.conf"
    mkdir -p /etc/sysctl.d

    if [[ ! -f "$bbr_conf_file" ]]; then
        print_status "INFO" "创建 $bbr_conf_file..."
        cat > "$bbr_conf_file" <<'EOF'
# ---- added by alpine-init.sh for BBR ----
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
        chmod 644 "$bbr_conf_file"
        sysctl -p "$bbr_conf_file" >/dev/null 2>&1
        check_result $? "BBR 已尝试启用（需内核支持）" "sysctl 加载失败"
    else
        print_status "INFO" "BBR 配置文件 $bbr_conf_file 已存在，跳过创建。"
        sysctl -p "$bbr_conf_file" >/dev/null 2>&1
        check_result $? "BBR 配置已加载" "BBR 配置加载失败"
    fi
}

# ========== 7) 设置自动安全更新 ==========
setup_auto_updates() {
    record_execution "7" "设置自动安全更新"
    print_status "PROGRESS" "创建 /etc/periodic/daily/apk-auto-upgrade 并启用 crond"
    local update_script_path="/etc/periodic/daily/apk-auto-upgrade"
    local expected_content
    expected_content=$'#!/bin/sh\napk -U update\napk upgrade --available'

    if [[ -f "$update_script_path" ]] && cmp -s <(echo "$expected_content") "$update_script_path"; then
        print_status "INFO" "自动更新脚本已存在，跳过创建。"
    else
        print_status "PROGRESS" "创建或更新 $update_script_path..."
        cat > "$update_script_path" <<'EOF'
#!/bin/sh
apk -U update
apk upgrade --available
EOF
        chmod +x "$update_script_path"
        check_result $? "自动更新脚本已创建" "自动更新脚本创建失败"
    fi

    rc-update add crond >/dev/null 2>&1 || true
    rc-service crond start >/dev/null 2>&1 || true
    print_status "SUCCESS" "已启用每日自动升级（crond + /etc/periodic/daily）"
}

# ========== 8) 系统安全审计 ==========
security_audit() {
    record_execution "8" "系统安全审计"
    local lynis_pkg="lynis"
    if grep -qE '^[[:space:]]*@edge_testing[[:space:]]+' /etc/apk/repositories 2>/dev/null; then
        lynis_pkg="lynis@edge_testing"
    fi

    print_status "PROGRESS" "安装 Lynis 并执行审计"
    if apk add --no-cache "$lynis_pkg" >/dev/null 2>&1; then
        lynis audit system || true
        print_status "SUCCESS" "Lynis 审计已运行（输出见终端或日志）"
    else
        print_status "WARNING" "Lynis 安装失败。若已启用 tagged 仓库，请使用：apk add --no-cache lynis@edge_testing"
    fi
}

# ========== 9) 安装 Docker==========
install_docker() {
    record_execution "9" "安装 Docker"
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

# ========== 10) 配置 SSH 公钥 ==========
configure_ssh_keys() {
    record_execution "10" "配置 SSH 公钥"
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

# ========== 11) 显示 SSH 主机密钥指纹 ==========
show_ssh_fingerprints() {
    record_execution "11" "显示 SSH 主机密钥指纹"
    print_status "INFO" "ECDSA:"
    ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null || true
    print_status "INFO" "ED25519:"
    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || true
    print_status "INFO" "RSA:"
    ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null || true
}

# ========== 12) 创建自定义用户 ==========
create_custom_user() {
    record_execution "12" "创建自定义用户"
    local NEW_USER
    read -rp "[?] 输入新用户名: " NEW_USER
    if [[ -z "$NEW_USER" ]]; then
        print_status "WARNING" "未输入用户名，已跳过"
        return 0
    fi
    if id "$NEW_USER" >/dev/null 2>&1; then
        print_status "ERROR" "用户 $NEW_USER 已存在"
        return 1
    fi

    # 可选 shell，默认 /bin/bash
    local DEFAULT_SHELL="/bin/bash"
    if command -v zsh >/dev/null 2>&1; then
        DEFAULT_SHELL="/bin/zsh"
    fi
    read -rp "[?] 登录 shell（默认 $DEFAULT_SHELL）: " USER_SHELL
    [[ -z "$USER_SHELL" ]] && USER_SHELL="$DEFAULT_SHELL"

    # BusyBox adduser 不加 -D 会交互要求设置密码，这里使用 -D 避免重复密码提示
    adduser -D -s "$USER_SHELL" "$NEW_USER"
    check_result $? "用户 $NEW_USER 已创建（shell: $USER_SHELL）" "创建用户失败" || return 1

    print_status "INFO" "为 $NEW_USER 设置密码："
    passwd "$NEW_USER"
    check_result $? "用户 $NEW_USER 密码已设置" "设置密码失败（用户已创建，可稍后手动执行 passwd $NEW_USER）" || return 1

    # 安装 sudo 并启用 wheel 组 sudo 权限（兼容 /etc/sudoers 不含 %wheel 的场景）
    apk add --no-cache sudo >/dev/null 2>&1 || true
    addgroup -S wheel >/dev/null 2>&1 || true
    ensure_wheel_sudoers || return 1
    if ! addgroup "$NEW_USER" wheel >/dev/null 2>&1; then
        if ! id -nG "$NEW_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "wheel"; then
            print_status "ERROR" "将 $NEW_USER 加入 wheel 组失败"
            return 1
        fi
    fi

    print_status "SUCCESS" "已将 $NEW_USER 加入 wheel 组并启用 sudo"
}

# ========== 13) 设置系统时区 ==========
configure_timezone() {
    record_execution "13" "设置系统时区"
    local zoneinfo_base="/usr/share/zoneinfo"
    local current_tz=""
    local tz_input=""
    local use_wizard=""

    print_status "PROGRESS" "配置系统时区（优先向导，失败时手动设置）"
    apk add --no-cache tzdata >/dev/null 2>&1 || true

    if command -v setup-timezone >/dev/null 2>&1; then
        read -r -p "[?] 是否使用 setup-timezone 向导？[Y/n]: " use_wizard
        case "$use_wizard" in
            n|N)
                print_status "INFO" "已跳过向导，进入手动设置。"
                ;;
            *)
                if setup-timezone; then
                    if [[ -f /etc/timezone ]]; then
                        current_tz="$(cat /etc/timezone 2>/dev/null)"
                    fi
                    if [[ -z "$current_tz" && -L /etc/localtime ]]; then
                        current_tz="$(readlink -f /etc/localtime 2>/dev/null | sed "s#^${zoneinfo_base}/##")"
                    fi

                    if [[ -n "$current_tz" ]]; then
                        print_status "SUCCESS" "系统时区已设置为: $current_tz"
                    elif [[ -e /etc/localtime ]]; then
                        print_status "SUCCESS" "时区已更新（检测到 /etc/localtime）。"
                        print_status "INFO" "Alpine 某些环境不依赖 /etc/timezone。"
                    else
                        print_status "WARNING" "向导已执行，但未检测到 /etc/localtime，转为手动设置。"
                        use_wizard="n"
                    fi

                    if [[ "$use_wizard" != "n" ]]; then
                        print_status "INFO" "当前系统时间: $(date '+%Y-%m-%d %H:%M:%S %z %Z')"
                        return 0
                    fi
                else
                    print_status "WARNING" "setup-timezone 执行失败，转为手动设置。"
                    use_wizard="n"
                fi
                ;;
        esac
    else
        print_status "WARNING" "未找到 setup-timezone，使用手动设置。"
        use_wizard="n"
    fi

    # 手动设置兜底：不依赖 /etc/timezone，/etc/localtime 为主
    print_status "INFO" "可用示例：Asia/Shanghai、UTC、America/New_York"
    read -r -p "[?] 输入时区（默认 UTC）: " tz_input
    [[ -z "$tz_input" ]] && tz_input="UTC"

    if [[ ! -f "${zoneinfo_base}/${tz_input}" ]]; then
        print_status "ERROR" "无效时区: $tz_input（不存在 ${zoneinfo_base}/${tz_input}）"
        return 1
    fi

    ln -sf "${zoneinfo_base}/${tz_input}" /etc/localtime
    echo "$tz_input" > /etc/timezone 2>/dev/null || true

    if [[ -L /etc/localtime ]]; then
        current_tz="$(readlink -f /etc/localtime 2>/dev/null | sed "s#^${zoneinfo_base}/##")"
    fi
    [[ -z "$current_tz" && -f /etc/timezone ]] && current_tz="$(cat /etc/timezone 2>/dev/null)"

    if [[ -n "$current_tz" || -e /etc/localtime ]]; then
        [[ -z "$current_tz" ]] && current_tz="$tz_input"
        print_status "SUCCESS" "系统时区已设置为: $current_tz"
        print_status "INFO" "当前系统时间: $(date '+%Y-%m-%d %H:%M:%S %z %Z')"
        return 0
    fi

    print_status "ERROR" "时区设置后仍无法确认，请手动检查 /etc/localtime"
    return 1
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
        "启用 edge 仓库"
        "安装基础软件包"
        "同步系统时间"
        "启用 TCP BBR"
        "设置自动安全更新"
        "系统安全审计（Lynis）"
        "安装 Docker"
        "配置 SSH 公钥"
        "显示 SSH 主机密钥指纹"
        "创建自定义用户（含 sudo/wheel）"
        "设置系统时区"
    )

    for i in $(seq 1 ${#menu_items[@]}); do
        if is_executed "$i"; then
            local exec_time
            exec_time=$(get_execution_time "$i")
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
        if ! read -rp "请输入序号 (0-15): " choice; then
            print_status "WARNING" "输入结束，已退出"
            exit 0
        fi
        case "$choice" in
            1) change_hostname ;;
            2) configure_ssh ;;
            3) setup_edge_repo ;;
            4) install_basic_packages ;;
            5) sync_system_time ;;
            6) enable_bbr ;;
            7) setup_auto_updates ;;
            8) security_audit ;;
            9) install_docker ;;
            10) configure_ssh_keys ;;
            11) show_ssh_fingerprints ;;
            12) create_custom_user ;;
            13) configure_timezone ;;
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

        if [[ "$choice" =~ ^([1-9]|1[0-5])$ ]]; then
            echo ""
            if ! read -rp "[?] 按回车键返回菜单..."; then
                print_status "WARNING" "输入结束，已退出"
                exit 0
            fi
        fi
    done
}

main
