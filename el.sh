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
SCRIPT_USER="${SUDO_USER:-$(whoami)}"
readonly SCRIPT_USER
USER_HOME="$(getent passwd "$SCRIPT_USER" | cut -d: -f6)"
[[ -z "$USER_HOME" ]] && USER_HOME="$HOME"
[[ -z "$USER_HOME" ]] && USER_HOME="/root"
readonly LOG_DIR="$USER_HOME/.local/state/init"
readonly LOG_FILE="$LOG_DIR/el-init.log"
readonly CONFIG_FILE="$LOG_DIR/el-init.conf"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'

# 初始化日志文件
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR" 2>/dev/null || true
touch "$LOG_FILE" "$CONFIG_FILE" 2>/dev/null
chmod 600 "$LOG_FILE" "$CONFIG_FILE" 2>/dev/null || true

# 统一输出函数
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
        "SKIP")
            echo -e "${PURPLE}[>]${NC} $message"
            echo "$timestamp [SKIP] $message" >> "$LOG_FILE"
            ;;
        "INPUT")
            echo -e "${WHITE}[?]${NC} $message"
            echo "$timestamp [INPUT] $message" >> "$LOG_FILE"
            ;;
    esac
}

# 检查命令执行结果
check_result() {
    local cmd_result=$1
    local success_msg="$2"
    local error_msg="$3"
    
    if [[ $cmd_result -eq 0 ]]; then
        [[ -n "$success_msg" ]] && print_status "SUCCESS" "$success_msg"
        return 0
    else
        [[ -n "$error_msg" ]] && print_status "ERROR" "$error_msg"
        return 1
    fi
}

# 获取项目执行时间
get_execution_time() {
    local item_number=$1
    grep "^$item_number|" "$CONFIG_FILE" | tail -n 1 | cut -d'|' -f2 2>/dev/null
}

# 记录执行的项目
record_execution() {
    local item_number=$1
    local item_name="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    if is_executed "$item_number"; then
        local temp_file
        temp_file=$(mktemp)
        grep -v "^$item_number|" "$CONFIG_FILE" > "$temp_file" 2>/dev/null || true
        echo "$item_number|$timestamp|$item_name" >> "$temp_file"
        mv "$temp_file" "$CONFIG_FILE"
    else
        echo "$item_number|$timestamp|$item_name" >> "$CONFIG_FILE"
    fi
}

# 检查项目是否已执行
is_executed() {
    local item_number=$1
    grep -q "^$item_number|" "$CONFIG_FILE" 2>/dev/null
}

run_menu_item() {
    local item_number=$1
    local item_name="$2"
    local status
    shift 2

    "$@"
    status=$?
    if [[ $status -eq 0 ]]; then
        record_execution "$item_number" "$item_name"
        return 0
    fi
    if [[ $status -eq 77 ]]; then
        return 0
    fi
    return "$status"
}

# 检查操作系统
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_status "ERROR" "无法检测操作系统类型"
        exit 1
    fi
    
    source /etc/os-release

    local pretty_name="${PRETTY_NAME:-$ID $VERSION_ID}"
    local os_ids=" $ID ${ID_LIKE:-} "
    if [[ "$ID" =~ ^(rhel|rocky|almalinux|ol|centos)$ || "$os_ids" == *" rhel "* || "$os_ids" == *" centos "* ]]; then
        OS_FAMILY=el
        EL_VERSION="${PLATFORM_ID##*:el}"
        EL_VERSION="${EL_VERSION:-${VERSION_ID%%.*}}"
        if [[ ! "$EL_VERSION" =~ ^(9|10)$ ]]; then
            print_status "ERROR" "仅支持 EL 9/10，当前系统: $pretty_name"
            exit 1
        fi
        SSH_SERVICE=sshd
        CHRONY_SERVICE=chronyd
        CHRONY_CONF=/etc/chrony.conf
        ADMIN_GROUP=wheel
    elif [[ "$os_ids" == *" ubuntu "* || "$os_ids" == *" debian "* ]]; then
        OS_FAMILY=debian
        DISTRO_BASE=debian
        DISTRO_CODENAME="${VERSION_CODENAME:-}"
        if [[ "$os_ids" == *" ubuntu "* || -n "${UBUNTU_CODENAME:-}" ]]; then
            DISTRO_BASE=ubuntu
            DISTRO_CODENAME="${UBUNTU_CODENAME:-$DISTRO_CODENAME}"
            if [[ ! "$DISTRO_CODENAME" =~ ^(noble|resolute)$ ]]; then
                print_status "ERROR" "仅支持 Ubuntu 24.04/26.04 LTS 及其衍生系统: $pretty_name"
                exit 1
            fi
        else
            local debian_version
            debian_version=$(cut -d. -f1 /etc/debian_version 2>/dev/null)
            case "$debian_version" in
                12) DISTRO_CODENAME=bookworm ;;
                13) DISTRO_CODENAME=trixie ;;
                *)
                    print_status "ERROR" "仅支持 Debian 12/13 及其衍生系统: $pretty_name"
                    exit 1
                    ;;
            esac
        fi
        SSH_SERVICE=ssh
        CHRONY_SERVICE=chrony
        CHRONY_CONF=/etc/chrony/chrony.conf
        ADMIN_GROUP=sudo
    else
        print_status "ERROR" "此脚本支持 EL 9/10、Debian、Ubuntu 及兼容衍生系统；Alpine 请使用 alpine.sh: $pretty_name"
        exit 1
    fi

    print_status "INFO" "操作系统检查通过: $pretty_name"
}

install_packages() {
    if [[ "$OS_FAMILY" == debian ]]; then
        sudo apt-get update && sudo apt-get install -y --no-install-recommends "$@"
    else
        sudo dnf install -y "$@"
    fi
}

enable_epel() {
    [[ "$OS_FAMILY" == el ]] || return 0
    rpm -q epel-release &>/dev/null && return 0
    sudo dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${EL_VERSION}.noarch.rpm"
    check_result $? "EPEL 仓库已启用" "EPEL 仓库启用失败"
}

# 用户确认函数
prompt_user() {
    local prompt="$1"
    local default="${2:-Y}"
    local choices="Y/n"
    [[ "${default^^}" == "N" ]] && choices="y/N"
    
    while true; do
        read -rp "$(echo -e "${WHITE}[?]${NC} $prompt ($choices): ")" response
        response=${response:-$default}
        case "${response,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) print_status "WARNING" "请输入 y 或 n" ;;
        esac
    done
}

# 检查端口是否被占用
check_port() {
    local port=$1
    ss -H -ltn | awk -v port="$port" '$4 ~ (":" port "$") { found=1 } END { exit !found }'
}

# 配置防火墙端口
configure_firewall_port() {
    local action=$1
    local port=$2

    if ! command -v firewall-cmd &>/dev/null || ! sudo firewall-cmd --state &>/dev/null; then
        if [[ "$OS_FAMILY" == debian ]] && command -v ufw &>/dev/null &&
            sudo env LC_ALL=C ufw status | grep -q '^Status: active'; then
            if [[ "$action" == add ]]; then
                sudo ufw allow "$port/tcp"
            else
                sudo ufw --force delete allow "$port/tcp"
            fi
            return $?
        fi
        print_status "ERROR" "需要运行中的 firewalld（Debian/Ubuntu 也可使用 UFW）管理 SSH 防火墙规则"
        return 1
    fi

    local -a zones=()
    local -a scope_args=()
    local zone
    local scope
    local failed=0

    if [[ "$action" == add ]]; then
        mapfile -t zones < <(sudo firewall-cmd --get-active-zones 2>/dev/null | awk '/^[^[:space:]]/ {print $1}')
    else
        read -ra zones <<< "$(sudo firewall-cmd --get-zones 2>/dev/null)"
    fi
    if (( ${#zones[@]} == 0 )); then
        print_status "ERROR" "未检测到 firewalld zone"
        return 1
    fi

    for scope in runtime permanent; do
        scope_args=()
        [[ "$scope" == permanent ]] && scope_args=(--permanent)
        for zone in "${zones[@]}"; do
            if [[ "$action" == add ]]; then
                sudo firewall-cmd "${scope_args[@]}" --zone="$zone" --query-port="$port"/tcp &>/dev/null ||
                    sudo firewall-cmd "${scope_args[@]}" --zone="$zone" --add-port="$port"/tcp &>/dev/null || failed=1
            else
                if sudo firewall-cmd "${scope_args[@]}" --zone="$zone" --query-port="$port"/tcp &>/dev/null &&
                    ! sudo firewall-cmd "${scope_args[@]}" --zone="$zone" --remove-port="$port"/tcp &>/dev/null; then
                    failed=1
                fi
                if [[ "$port" == 22 ]] && \
                    sudo firewall-cmd "${scope_args[@]}" --zone="$zone" --query-service=ssh &>/dev/null &&
                    ! sudo firewall-cmd "${scope_args[@]}" --zone="$zone" --remove-service=ssh &>/dev/null; then
                    failed=1
                fi
            fi
        done
    done

    if [[ $failed -ne 0 ]]; then
        print_status "ERROR" "防火墙端口操作失败: $port/tcp"
        return 1
    fi
    if [[ "$action" == add ]]; then
        print_status "SUCCESS" "SSH 防火墙端口已开放: $port/tcp"
    else
        print_status "SUCCESS" "旧 SSH 防火墙规则已清理: $port/tcp"
    fi
}

get_journald_setting() {
    local key=$1
    awk -v key="$key" '
        /^[[:space:]]*\[/ {
            in_journal = $0 ~ /^[[:space:]]*\[Journal\][[:space:]]*$/
            next
        }
        in_journal && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            value = $0
            sub(/^[^=]*=[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
        }
        END { print value }
    '
}

# 系统检查函数
pre_check() {
    print_status "INFO" "执行系统检查"

    if sudo -n true 2>/dev/null; then
        print_status "SUCCESS" "sudo 权限检查通过"
    elif sudo true 2>/dev/null; then
        print_status "SUCCESS" "sudo 权限验证成功"
    else
        print_status "WARNING" "当前用户没有 sudo 权限，部分功能可能无法使用"
    fi

    local avail_kb
    avail_kb=$(df --output=avail / | tail -1 | tr -d ' ' 2>/dev/null)
    if [[ -z "$avail_kb" || ! "$avail_kb" =~ ^[0-9]+$ ]]; then
        print_status "WARNING" "无法准确获取磁盘剩余空间"
    else
        local avail_gb=$((avail_kb / 1024 / 1024))
        if [[ $avail_kb -lt 1048576 ]]; then
            print_status "WARNING" "硬盘剩余空间不足 1GB (当前: ${avail_gb}GB)，可能影响软件安装"
        else
            print_status "SUCCESS" "硬盘剩余空间: ${avail_gb}GB"
        fi
    fi
    local cpu_model
    local cpu_cores
    local mem_total_mb
    local mem_available_mb
    local swap_total_mb
    cpu_model=$(awk -F: '/model name/{gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null)
    cpu_cores=$(nproc 2>/dev/null || echo "未知")
    mem_total_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
    mem_available_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
    swap_total_mb=$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
    print_status "INFO" "CPU: ${cpu_model:-未知} (${cpu_cores} 核)"
    print_status "INFO" "内存: ${mem_available_mb:-未知}MB 可用 / ${mem_total_mb:-未知}MB 总计"
    print_status "INFO" "Swap: ${swap_total_mb:-未知}MB"

    local service update_timer=dnf-automatic-install.timer
    [[ "$OS_FAMILY" == debian ]] && update_timer=apt-daily-upgrade.timer
    for service in "$SSH_SERVICE" "$CHRONY_SERVICE" docker "$update_timer" systemd-journald init-aide-check.timer; do
        if systemctl list-unit-files "$service" --no-legend 2>/dev/null | grep -q . || systemctl status "$service" &>/dev/null; then
            if systemctl is-active --quiet "$service"; then
                print_status "SUCCESS" "$service: active"
            else
                print_status "WARNING" "$service: inactive"
            fi
        else
            print_status "INFO" "$service: 未安装或未注册"
        fi
    done

    local current_congestion_control
    current_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [[ "$current_congestion_control" == "bbr" ]]; then
        print_status "SUCCESS" "BBR: 已生效"
    else
        print_status "INFO" "BBR: 当前拥塞控制为 ${current_congestion_control:-未知}"
    fi

    local loaded_journald_config
    if loaded_journald_config=$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null) && \
       [[ "$(get_journald_setting Storage <<< "$loaded_journald_config")" == "persistent" ]] && \
       sudo find /var/log/journal -maxdepth 2 -type f -name '*.journal*' -print -quit 2>/dev/null | grep -q .; then
        print_status "SUCCESS" "journald: 已持久化写入 /var/log/journal"
    else
        print_status "INFO" "journald: 未确认持久化写入"
    fi

    if sudo test -f /var/lib/aide/aide.db.gz || sudo test -f /var/lib/aide/aide.db; then
        print_status "SUCCESS" "AIDE: 数据库已存在"
    else
        print_status "INFO" "AIDE: 未检测到数据库"
    fi
    if systemctl is-failed --quiet init-aide-check.service 2>/dev/null; then
        print_status "WARNING" "AIDE 检查异常，请查看 journalctl -u init-aide-check.service"
    fi
}

# 1. 设置代理
setup_proxy() {
    print_status "INFO" "配置 HTTP 代理"

    read -rp "$(echo -e "${WHITE}[?]${NC} 代理地址 (host:port，留空跳过): ")" proxy_address

    if [[ -z "$proxy_address" ]]; then
        print_status "SKIP" "代理设置已跳过"
        return 77
    fi

    # 验证代理地址格式
    if [[ ! "$proxy_address" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
        print_status "ERROR" "代理地址格式无效"
        return 1
    fi

    # 设置 HTTP 代理环境变量
    export http_proxy="http://$proxy_address"
    export https_proxy="http://$proxy_address"
    export HTTP_PROXY="http://$proxy_address"
    export HTTPS_PROXY="http://$proxy_address"

    print_status "SUCCESS" "HTTP 代理已设置: $proxy_address"
}

# 2. 修改主机名
change_hostname() {
    print_status "INFO" "当前主机名: $(hostname)"
    
    read -rp "$(echo -e "${WHITE}[?]${NC} 新主机名: ")" new_hostname
    
    if [[ -z "$new_hostname" ]]; then
        print_status "ERROR" "主机名不能为空"
        return 1
    fi
    
    # 验证主机名格式
    if [[ ! "$new_hostname" =~ ^[a-zA-Z0-9-]+$ ]]; then
        print_status "ERROR" "主机名格式无效（只允许字母、数字和连字符）"
        return 1
    fi
    
    sudo hostnamectl set-hostname "$new_hostname"
    check_result $? "主机名已更改为: $new_hostname" "主机名更改失败"
}

# 3. 关闭 SELinux
disable_selinux() {
    if [[ "$OS_FAMILY" != el ]]; then
        print_status "SKIP" "此项仅适用于 EL 的 SELinux"
        return 77
    fi
    local current_status
    current_status=$(getenforce 2>/dev/null || echo "Unknown")
    print_status "INFO" "当前 SELinux 状态: $current_status"
    
    # SELinux 安全警告
    echo -e "\n${RED}=== SELinux 安全警告 ===${NC}"
    echo -e "${YELLOW}[!]${NC} SELinux 是一个重要的安全机制，它提供："
    echo -e "    • 强制访问控制 (MAC)"
    echo -e "    • 进程权限限制"
    echo -e "    • 文件系统安全标签"
    echo -e "    • 网络访问控制"
    echo -e "\n${YELLOW}[!]${NC} 关闭 SELinux 可能会："
    echo -e "    • 降低系统整体安全性"
    echo -e "    • 增加恶意软件攻击风险"
    echo -e "    • 移除重要的安全边界"
    echo -e "${RED}========================${NC}\n"
    
    if ! prompt_user "确认要关闭 SELinux 吗？" "N"; then
        print_status "SKIP" "SELinux 保持当前状态"
        return 77
    fi
    
    print_status "PROGRESS" "禁用 SELinux"
    
    sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config &>/dev/null
    check_result $? "" "SELinux 配置修改失败" || return 1
    if [[ "$current_status" == "Enforcing" ]]; then
        sudo setenforce 0 &>/dev/null
        check_result $? "" "SELinux 运行状态修改失败" || return 1
    fi
    
    print_status "SUCCESS" "SELinux 已禁用（重启后生效）"
}

# 5. 配置 SSH
configure_ssh() {
    print_status "PROGRESS" "配置 SSH 端口"

    if systemctl is-active --quiet ssh.socket; then
        print_status "ERROR" "当前由 ssh.socket 监听；请先切换到 ssh.service 再使用端口迁移"
        return 1
    fi

    local ssh_config="/etc/ssh/sshd_config"
    if ! sudo test -r "$ssh_config"; then
        print_status "ERROR" "无法读取 $ssh_config"
        return 1
    fi

    local -a old_ssh_ports=()
    mapfile -t old_ssh_ports < <(
        sudo sshd -T -f "$ssh_config" 2>/dev/null |
            awk '$1 == "port" && !seen[$2]++ { print $2 }'
    )
    if (( ${#old_ssh_ports[@]} == 0 )); then
        print_status "ERROR" "无法确定当前 SSH 端口"
        return 1
    fi

    local ssh_port
    local old_ssh_port
    local port_is_current
    while true; do
        read -rp "$(echo -e "${WHITE}[?]${NC} SSH 端口号 (22-65535，默认 2222): ")" ssh_port
        ssh_port=${ssh_port:-2222}

        if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || [[ $ssh_port -lt 22 ]] || [[ $ssh_port -gt 65535 ]]; then
            print_status "ERROR" "端口号无效，请输入 22-65535 之间的数字"
            continue
        fi

        port_is_current=false
        for old_ssh_port in "${old_ssh_ports[@]}"; do
            [[ "$old_ssh_port" == "$ssh_port" ]] && port_is_current=true
        done
        if [[ "$port_is_current" == false ]] && check_port "$ssh_port"; then
            print_status "ERROR" "端口 $ssh_port 已被占用"
            continue
        fi
        break
    done

    local ssh_config_backup
    ssh_config_backup="${ssh_config}.bak.$(date +%Y%m%d%H%M%S)"
    if ! sudo cp -a "$ssh_config" "$ssh_config_backup"; then
        print_status "ERROR" "SSH 配置备份失败"
        return 1
    fi

    if ! sudo sed -Ei \
        -e "1iPort $ssh_port" \
        -e '0,/^[[:space:]]*Match([[:space:]]|$)/I{/^[[:space:]]*Port[[:space:]]+/Id;}' \
        "$ssh_config"; then
        sudo cp -a "$ssh_config_backup" "$ssh_config" &>/dev/null || true
        print_status "ERROR" "SSH 端口写入失败，已回滚"
        return 1
    fi

    if ! sudo sshd -t -f "$ssh_config" &>/dev/null; then
        sudo cp -a "$ssh_config_backup" "$ssh_config" &>/dev/null || true
        print_status "ERROR" "新 SSH 配置校验失败，已回滚"
        return 1
    fi

    local -a new_ssh_ports=()
    mapfile -t new_ssh_ports < <(
        sudo sshd -T -f "$ssh_config" 2>/dev/null |
            awk '$1 == "port" && !seen[$2]++ { print $2 }'
    )
    if (( ${#new_ssh_ports[@]} != 1 )) || [[ "${new_ssh_ports[0]}" != "$ssh_port" ]]; then
        sudo cp -a "$ssh_config_backup" "$ssh_config" &>/dev/null || true
        print_status "ERROR" "新 SSH 端口未正确生效，已回滚"
        return 1
    fi

    local selinux_state
    selinux_state=$(getenforce 2>/dev/null || echo Disabled)
    if [[ "$selinux_state" != Disabled && "$ssh_port" != 22 ]]; then
        if ! command -v semanage &>/dev/null; then
            sudo dnf install -y policycoreutils-python-utils
            if ! check_result $? "SELinux 管理工具已安装" "SELinux 管理工具安装失败"; then
                sudo cp -a "$ssh_config_backup" "$ssh_config" &>/dev/null || true
                return 1
            fi
        fi
        if ! sudo semanage port -l 2>/dev/null | grep -qE "^ssh_port_t[[:space:]]+tcp.*\\b${ssh_port}\\b"; then
            if ! sudo semanage port -a -t ssh_port_t -p tcp "$ssh_port" &>/dev/null; then
                sudo cp -a "$ssh_config_backup" "$ssh_config" &>/dev/null || true
                print_status "ERROR" "SELinux SSH 端口策略配置失败"
                return 1
            fi
        fi
    fi

    if ! configure_firewall_port add "$ssh_port"; then
        sudo cp -a "$ssh_config_backup" "$ssh_config" &>/dev/null || true
        print_status "ERROR" "新 SSH 端口未能完整放行，配置已回滚"
        return 1
    fi

    local ssh_ready=false
    local attempt
    if sudo systemctl reload "$SSH_SERVICE" &>/dev/null; then
        for (( attempt = 0; attempt < 10; attempt++ )); do
            sleep 0.5
            if check_port "$ssh_port"; then
                ssh_ready=true
                break
            fi
        done
    fi
    if [[ "$ssh_ready" == false ]]; then
        sudo cp -a "$ssh_config_backup" "$ssh_config" &>/dev/null || true
        sudo systemctl reload "$SSH_SERVICE" &>/dev/null || true
        print_status "ERROR" "SSH 未能在新端口监听，配置已回滚"
        return 1
    fi

    local firewall_cleanup_failed=0
    for old_ssh_port in "${old_ssh_ports[@]}"; do
        [[ "$old_ssh_port" == "$ssh_port" ]] && continue
        configure_firewall_port remove "$old_ssh_port" || firewall_cleanup_failed=1
    done
    if [[ $firewall_cleanup_failed -ne 0 ]]; then
        print_status "ERROR" "SSH 已切换到端口 $ssh_port，但旧防火墙规则清理不完整"
        return 1
    fi

    print_status "SUCCESS" "SSH 配置完成，端口: $ssh_port，备份: $ssh_config_backup"
    print_status "WARNING" "确认公钥登录可用后，请手动设置："
    print_status "INFO" "PermitRootLogin no"
    print_status "INFO" "PasswordAuthentication no"
    print_status "INFO" "KbdInteractiveAuthentication no"
    print_status "INFO" "PermitEmptyPasswords no"
}

# 6. 安装基础软件包
install_basic_packages() {
    print_status "PROGRESS" "安装基础软件包"

    local archive_package="7zip"
    local packages=("$archive_package" "wget" "git" "vim" "atop" "sysstat" "tmux")
    
    if [[ "$OS_FAMILY" == debian ]]; then
        sudo apt-get update && sudo apt-get upgrade -y || return 1
    else
        sudo dnf update -y || return 1
    fi
    enable_epel || return 1
    install_packages "${packages[@]}"
    check_result $? "基础软件包安装完成" "基础软件包安装失败"
}

# 7. 安装 ZSH 工具链
install_zsh_tools() {
    print_status "PROGRESS" "安装 ZSH 和相关工具"

    local zsh_user
    local zsh_home
    read -rp "$(echo -e "${WHITE}[?]${NC} ZSH 工具链安装目标用户（默认 $SCRIPT_USER）: ")" zsh_user
    zsh_user=${zsh_user:-$SCRIPT_USER}

    if ! id -u "$zsh_user" &>/dev/null; then
        print_status "ERROR" "用户不存在: $zsh_user"
        return 1
    fi

    zsh_home="$(getent passwd "$zsh_user" | cut -d: -f6)"
    if [[ -z "$zsh_home" || ! -d "$zsh_home" ]]; then
        print_status "ERROR" "无法找到 $zsh_user 的 home 目录"
        return 1
    fi

    if ! prompt_user "确认要为 $zsh_user 安装 ZSH 工具链"; then
        print_status "SKIP" "已跳过 ZSH 工具链安装"
        return 77
    fi

    print_status "PROGRESS" "安装 ZSH、Git 和 FZF"
    enable_epel || return 1
    install_packages zsh git fzf
    check_result $? "ZSH 相关软件包安装完成" "ZSH 相关软件包安装失败" || return 1
    if ! command -v curl &>/dev/null; then
        install_packages curl
        check_result $? "curl 安装完成" "curl 安装失败" || return 1
    fi

    local -a as_zsh_user=(sudo -H -u "$zsh_user")
    local zshrc="$zsh_home/.zshrc"
    local zsh_path
    if ! zsh_path="$("${as_zsh_user[@]}" sh -c 'command -v zsh')" || [[ -z "$zsh_path" ]]; then
        print_status "ERROR" "无法确定 ZSH 可执行文件路径"
        return 1
    fi

    local omz_dir="$zsh_home/.oh-my-zsh"
    local omz_main="$omz_dir/oh-my-zsh.sh"
    if [[ ! -f "$omz_main" ]]; then
        if [[ -e "$omz_dir" || -L "$omz_dir" ]]; then
            print_status "ERROR" "检测到不完整的 Oh My Zsh 路径: $omz_dir，请处理后重试"
            return 1
        fi

        print_status "PROGRESS" "安装 Oh My Zsh"
        local omz_install_script
        if ! omz_install_script="$(mktemp)"; then
            print_status "ERROR" "无法创建 Oh My Zsh 临时安装文件"
            return 1
        fi
        if ! curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -o "$omz_install_script"; then
            rm -f "$omz_install_script"
            print_status "ERROR" "Oh My Zsh 安装脚本下载失败"
            return 1
        fi
        if ! "${as_zsh_user[@]}" sh -c "cd \"\$HOME\" && exec sh -s -- \"\$@\"" sh \
            --unattended < "$omz_install_script"; then
            rm -f "$omz_install_script"
            print_status "ERROR" "Oh My Zsh 安装失败"
            return 1
        fi
        rm -f "$omz_install_script"
        print_status "SUCCESS" "Oh My Zsh 安装完成"
    fi

    if [[ ! -e "$zshrc" && ! -L "$zshrc" ]]; then
        "${as_zsh_user[@]}" cp "$omz_dir/templates/zshrc.zsh-template" "$zshrc"
        check_result $? "已从 Oh My Zsh 默认模板生成配置" "ZSH 默认配置生成失败" || return 1
    fi

    local zsh_custom="$omz_dir/custom"
    "${as_zsh_user[@]}" mkdir -p "$zsh_custom/plugins"
    check_result $? "Oh My Zsh 自定义目录已准备" "自定义目录创建失败" || return 1

    local plugin_name
    local plugin_dir
    for plugin_name in zsh-autosuggestions zsh-syntax-highlighting; do
        plugin_dir="$zsh_custom/plugins/$plugin_name"
        if [[ -f "$plugin_dir/$plugin_name.plugin.zsh" ]]; then
            continue
        fi
        if [[ -e "$plugin_dir" || -L "$plugin_dir" ]]; then
            print_status "ERROR" "检测到不完整的插件目录: $plugin_dir，请处理后重试"
            return 1
        fi
        print_status "PROGRESS" "安装 $plugin_name 插件"
        "${as_zsh_user[@]}" git clone --depth=1 "https://github.com/zsh-users/$plugin_name.git" "$plugin_dir"
        check_result $? "$plugin_name 插件安装完成" "$plugin_name 插件安装失败" || return 1
    done

    local required_zsh_file
    for required_zsh_file in \
        "$omz_main" \
        "$omz_dir/themes/bira.zsh-theme" \
        "$omz_dir/plugins/git/git.plugin.zsh" \
        "$omz_dir/plugins/fzf/fzf.plugin.zsh" \
        "$omz_dir/plugins/sudo/sudo.plugin.zsh" \
        "$omz_dir/plugins/colored-man-pages/colored-man-pages.plugin.zsh" \
        "$zsh_custom/plugins/zsh-autosuggestions/zsh-autosuggestions.plugin.zsh" \
        "$zsh_custom/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.plugin.zsh"
    do
        if ! "${as_zsh_user[@]}" test -r "$required_zsh_file"; then
            print_status "ERROR" "ZSH 组件不可读: $required_zsh_file"
            return 1
        fi
    done

    local zsh_plugins='plugins=(git fzf sudo colored-man-pages zsh-autosuggestions zsh-syntax-highlighting)'
    "${as_zsh_user[@]}" sed -Ei \
        -e 's/^ZSH_THEME=.*/ZSH_THEME="bira"/' \
        -e "s/^plugins=\\([^)]*\\)\$/$zsh_plugins/" \
        "$zshrc"
    check_result $? "ZSH 主题和插件配置完成" "ZSH 主题或插件配置失败" || return 1

    if ! "${as_zsh_user[@]}" grep -Fxq 'ZSH_THEME="bira"' "$zshrc" || \
        ! "${as_zsh_user[@]}" grep -Fxq "$zsh_plugins" "$zshrc"; then
        print_status "ERROR" "未能识别 Oh My Zsh 默认配置格式"
        return 1
    fi

    if ! "${as_zsh_user[@]}" grep -Fq '# 自定义 alias' "$zshrc"; then
        "${as_zsh_user[@]}" tee -a "$zshrc" >/dev/null <<'EOF'

# 自定义 alias
alias dunow='du -xhd 1'
alias rs='sudo systemctl restart'
alias st='sudo systemctl status'
alias docker='sudo docker'
EOF
        check_result $? "自定义 alias 添加完成" "alias 配置失败" || return 1
    else
        print_status "INFO" "自定义 alias 已存在，跳过追加"
    fi

    if ! "${as_zsh_user[@]}" "$zsh_path" -n "$zshrc"; then
        print_status "ERROR" "ZSH 配置语法检查失败: $zshrc"
        return 1
    fi

    local current_shell
    local zsh_real
    local current_shell_real
    current_shell="$(getent passwd "$zsh_user" | cut -d: -f7)"
    zsh_real="$(readlink -f "$zsh_path" 2>/dev/null || echo "$zsh_path")"
    current_shell_real="$(readlink -f "$current_shell" 2>/dev/null || echo "$current_shell")"
    if [[ "$current_shell" == "$zsh_path" || "$current_shell_real" == "$zsh_real" ]]; then
        print_status "INFO" "$zsh_user 的默认 shell 已经是 ZSH"
    else
        sudo usermod -s "$zsh_path" "$zsh_user"
        check_result $? "$zsh_user 的默认 shell 已更改为 ZSH" "默认 shell 更改失败" || return 1
    fi

    print_status "SUCCESS" "ZSH 工具链已为 $zsh_user 安装完成，请重新登录应用更改"
}

# 8. 同步系统时间
sync_system_time() {
    print_status "PROGRESS" "配置 NTS 时间同步"
    
    install_packages chrony
    check_result $? "Chrony 安装完成" "Chrony 安装失败" || return 1

    local chrony_conf="$CHRONY_CONF"
    sudo sed -Ei '/^[[:space:]]*(server|pool|peer|authselectmode)[[:space:]]/d' "$chrony_conf" &&
        sudo tee -a "$chrony_conf" >/dev/null <<'EOF'
authselectmode require
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
EOF
    check_result $? "NTS 时间源已配置" "NTS 时间源配置失败" || return 1

    sudo systemctl enable "$CHRONY_SERVICE" &>/dev/null && sudo systemctl restart "$CHRONY_SERVICE" &>/dev/null
    check_result $? "NTS 时间同步服务已启用" "NTS 时间同步配置失败" || return 1

    sudo chronyc -N authdata 2>/dev/null
}

# 9. 启用 TCP BBR
enable_bbr() {
    print_status "PROGRESS" "启用 BBR 拥塞控制"

    local bbr_conf="/etc/sysctl.d/99-bbr.conf"
    if ! sudo tee "$bbr_conf" >/dev/null <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    then
        print_status "ERROR" "BBR 配置写入失败"
        return 1
    fi

    if ! sudo sysctl -p "$bbr_conf" &>/dev/null; then
        print_status "ERROR" "BBR 配置加载失败"
        return 1
    fi

    local current_congestion_control
    current_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [[ "$current_congestion_control" == "bbr" ]]; then
        print_status "SUCCESS" "BBR 已启用"
    else
        print_status "WARNING" "BBR 未生效，当前拥塞控制: ${current_congestion_control:-未知}"
        return 1
    fi
}

# 10. 配置 Swap
configure_swap() {
    print_status "PROGRESS" "配置 Swap"
    swapon --show 2>/dev/null || cat /proc/swaps

    local swap_type swap_size_mb default_size_mb=4096
    while true; do
        read -rp "[?] 类型：1) 磁盘文件 2) zram 0) 跳过（默认 1）: " swap_type || return 77
        swap_type=${swap_type:-1}
        case "$swap_type" in
            1) break ;;
            2)
                default_size_mb=$(awk '/MemTotal/ {n=int($2/2048); print n<4096 ? n : 4096}' /proc/meminfo)
                break ;;
            0) return 77 ;;
            *) print_status "WARNING" "请输入 0、1 或 2" ;;
        esac
    done
    while true; do
        read -rp "[?] 大小（MiB，1024 MiB = 1 GiB，默认 $default_size_mb）: " swap_size_mb || return 77
        swap_size_mb=${swap_size_mb:-$default_size_mb}
        [[ "$swap_size_mb" =~ ^[1-9][0-9]*$ ]] && break
        print_status "WARNING" "请输入正整数 MiB，例如 512、2048 或 4096"
    done

    if ! command -v mkswap &>/dev/null || ! command -v swapon &>/dev/null; then
        install_packages util-linux
        check_result $? "Swap 工具安装完成" "Swap 工具安装失败" || return 1
    fi

    if [[ "$swap_type" == 2 ]]; then
        local zram_package=zram-generator
        [[ "$OS_FAMILY" == debian ]] && zram_package=systemd-zram-generator
        install_packages "$zram_package" kmod || return 1
        if [[ -n "$(sudo zramctl --noheadings)" ]]; then
            print_status "SKIP" "已有 zram 设备，保留当前配置；调整大小前请先停用对应设备"
            return 77
        fi
        if ! sudo modprobe zram; then
            print_status "ERROR" "当前内核无法加载 zram，现有 Swap 保持不变"
            return 1
        fi
        sudo mkdir -p /etc/systemd/zram-generator.conf.d || return 1
        sudo tee /etc/systemd/zram-generator.conf.d/80-init.conf >/dev/null <<EOF
[zram0]
zram-size = $swap_size_mb
swap-priority = 100
EOF
        check_result $? "zram 配置已写入" "zram 配置写入失败" || return 1
        sudo systemctl daemon-reload && sudo systemctl start dev-zram0.swap
        check_result $? "" "zram 启动失败" || return 1
        if ! awk '$1=="/dev/zram0" {found=1} END {exit !found}' /proc/swaps; then
            print_status "ERROR" "未检测到已启用的 zram Swap"
            return 1
        fi
        print_status "SUCCESS" "zram 已启用并配置开机启动: ${swap_size_mb} MiB，优先级 100"
        return 0
    fi

    local swap_file="/swapfile"
    if sudo test -L "$swap_file" || { sudo test -e "$swap_file" && ! sudo test -f "$swap_file"; }; then
        print_status "ERROR" "$swap_file 不是普通文件，拒绝覆盖"
        return 1
    fi
    if sudo test -e "$swap_file"; then
        print_status "WARNING" "$swap_file 已存在"
        if ! prompt_user "是否删除后按新大小创建" "N"; then
            print_status "SKIP" "已跳过 Swap 创建"
            return 77
        fi
        if awk -v file="$swap_file" '$1==file {found=1} END {exit !found}' /proc/swaps &&
            ! sudo swapoff "$swap_file"; then
            print_status "ERROR" "无法停用现有 Swap，保留原文件"
            return 1
        fi
        if ! sudo rm -f "$swap_file"; then
            print_status "ERROR" "删除旧 swapfile 失败: $swap_file"
            return 1
        fi
    fi

    print_status "PROGRESS" "创建 ${swap_size_mb} MiB swapfile"
    if ! {
        if command -v fallocate &>/dev/null; then
            sudo fallocate -l "${swap_size_mb}M" "$swap_file" 2>/dev/null || \
                sudo dd if=/dev/zero of="$swap_file" bs=1M count="$swap_size_mb"
        else
            sudo dd if=/dev/zero of="$swap_file" bs=1M count="$swap_size_mb"
        fi
    }; then
        print_status "ERROR" "swapfile 创建失败"
        sudo rm -f "$swap_file" 2>/dev/null || true
        return 1
    fi

    if ! sudo chmod 600 "$swap_file"; then
        print_status "ERROR" "设置 swapfile 权限失败"
        sudo rm -f "$swap_file" 2>/dev/null || true
        return 1
    fi

    if ! sudo mkswap "$swap_file"; then
        print_status "ERROR" "mkswap 失败"
        sudo rm -f "$swap_file" 2>/dev/null || true
        return 1
    fi

    if ! sudo swapon "$swap_file"; then
        print_status "ERROR" "swapon 失败，当前环境可能不支持 swapfile"
        sudo rm -f "$swap_file" 2>/dev/null || true
        return 1
    fi

    local fstab_entry="/swapfile none swap sw 0 0"
    if ! sudo awk -v file="$swap_file" '$1==file && $3=="swap" {found=1} END {exit !found}' /etc/fstab; then
        if ! echo "$fstab_entry" | sudo tee -a /etc/fstab >/dev/null; then
            print_status "ERROR" "Swap 持久化配置写入失败"
            if sudo swapoff "$swap_file" 2>/dev/null; then
                sudo rm -f "$swap_file" 2>/dev/null || true
            fi
            return 1
        fi
    fi

    print_status "SUCCESS" "Swap 已创建并启用: ${swap_size_mb} MiB"
    swapon --show 2>/dev/null || cat /proc/swaps
}

# 11. 设置自动更新
setup_auto_updates() {
    if [[ "$OS_FAMILY" == debian ]]; then
        install_packages unattended-upgrades || return 1
        sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
        check_result $? "自动更新配置已写入" "自动更新配置失败" || return 1
        sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
        check_result $? "已启用 unattended-upgrades，更新范围沿用发行版默认配置" "自动更新启用失败"
        return $?
    fi
    local upgrade_type="security"
    local update_scope="安全更新"
    if [[ "$ID" == "centos" ]]; then
        upgrade_type="default"
        update_scope="全部更新（CentOS Stream 无安全公告元数据）"
    fi

    print_status "PROGRESS" "配置自动更新: $update_scope"

    sudo dnf install -y dnf-automatic
    check_result $? "DNF automatic 安装完成" "安装失败" || return 1

    sudo sed -Ei "s/^[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = $upgrade_type/" \
        /etc/dnf/automatic.conf
    check_result $? "更新类型已配置: $update_scope" "更新配置失败" || return 1

    sudo systemctl enable --now dnf-automatic-install.timer
    check_result $? "自动更新已启用: $update_scope" "自动更新启用失败"
}

# 12. 配置 AIDE
configure_aide() {
    print_status "PROGRESS" "安装文件完整性检测工具"
    
    if [[ "$OS_FAMILY" == debian ]]; then
        install_packages aide aide-common
    else
        install_packages aide
    fi
    check_result $? "AIDE 安装完成" "AIDE 安装失败" || return 1

    local aide_conf=/etc/aide.conf
    local aide_new_db="/var/lib/aide/aide.db.new.gz"
    local aide_db="/var/lib/aide/aide.db.gz"
    if [[ "$OS_FAMILY" == debian ]]; then
        aide_conf=/etc/aide/aide.conf
        aide_new_db=/var/lib/aide/aide.db.new
        aide_db=/var/lib/aide/aide.db
    fi
    local aide_bin
    aide_bin=$(sudo sh -c 'command -v aide') || return 1

    if ! sudo tee /etc/systemd/system/init-aide-check.service >/dev/null <<EOF
[Unit]
Description=AIDE file integrity check

[Service]
Type=oneshot
ExecStart=$aide_bin --config=$aide_conf --check
Nice=19
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
EOF
    then
        print_status "ERROR" "AIDE 服务配置写入失败"
        return 1
    fi
    if ! sudo tee /etc/systemd/system/init-aide-check.timer >/dev/null <<'EOF'
[Unit]
Description=Daily AIDE file integrity check

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
    then
        print_status "ERROR" "AIDE 定时器配置写入失败"
        return 1
    fi
    sudo systemctl daemon-reload || return 1
    # 先创建开机链接，避免首次基线漏掉定时器自身的配置。
    sudo systemctl enable init-aide-check.timer || return 1

    if sudo test -e "$aide_db"; then
        print_status "INFO" "保留已有 AIDE 基线: $aide_db"
    else
        print_status "PROGRESS" "首次初始化 AIDE 基线（可能需要几分钟）"
        if ! sudo "$aide_bin" --config="$aide_conf" --init; then
            print_status "ERROR" "AIDE 数据库初始化失败"
            return 1
        fi
        if ! sudo test -s "$aide_new_db" || ! sudo mv -n "$aide_new_db" "$aide_db"; then
            print_status "ERROR" "AIDE 基线启用失败: $aide_db"
            return 1
        fi
    fi

    sudo systemctl start init-aide-check.timer
    check_result $? "AIDE 每日 04:00–04:30 检查已启用（本机时区），错过的检查会补跑" "AIDE 定时器启用失败" || return 1
    if [[ "$OS_FAMILY" == debian ]] && systemctl cat dailyaidecheck.timer &>/dev/null; then
        sudo systemctl disable --now dailyaidecheck.timer || return 1
    fi
    print_status "INFO" "异常会使 init-aide-check.service 进入 failed；查看报告: journalctl -u init-aide-check.service"
    print_status "INFO" "基线仅在首次创建；确认文件变更后再手动更新，不会自动接受变更"
}

# 13. Lynis 安全审计
run_lynis_audit() {
    print_status "PROGRESS" "执行 Lynis 安全审计"

    enable_epel || return 1
    install_packages lynis
    check_result $? "Lynis 安装完成" "Lynis 安装失败" || return 1

    print_status "PROGRESS" "运行 Lynis 安全扫描"
    sudo lynis audit system --quiet
    check_result $? "Lynis 审计完成，日志: /var/log/lynis.log" "Lynis 审计失败，日志: /var/log/lynis.log"
}

# 14. 安装 Docker
install_docker() {
    print_status "PROGRESS" "安装 Docker CE"

    if [[ "$OS_FAMILY" == debian ]]; then
        install_packages ca-certificates curl || return 1
        sudo install -m 0755 -d /etc/apt/keyrings || return 1
        sudo curl -fsSL "https://download.docker.com/linux/$DISTRO_BASE/gpg" -o /etc/apt/keyrings/docker.asc || return 1
        sudo chmod 644 /etc/apt/keyrings/docker.asc || return 1
        printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
            "$(dpkg --print-architecture)" "$DISTRO_BASE" "$DISTRO_CODENAME" |
            sudo tee /etc/apt/sources.list.d/docker.list >/dev/null || return 1
    else
        install_packages dnf-plugins-core || return 1
        local docker_distro=centos
        [[ "$ID" == rhel ]] && docker_distro=rhel
        sudo dnf config-manager --add-repo "https://download.docker.com/linux/$docker_distro/docker-ce.repo"
        check_result $? "Docker 仓库已配置" "Docker 仓库配置失败" || return 1
    fi

    install_packages docker-ce docker-ce-cli containerd.io
    check_result $? "Docker 安装完成" "Docker 安装失败" || return 1

    sudo systemctl enable --now docker &>/dev/null
    check_result $? "Docker 已安装并启动" "Docker 服务启用或启动失败"
}

validate_ssh_public_key() {
    [[ ! "$1" =~ (^|[[:space:]])ssh-dss([[:space:]]|$) ]] &&
        printf '%s\n' "$1" | ssh-keygen -lf - &>/dev/null
}

# 15. 配置 SSH 公钥
configure_ssh_keys() {
    print_status "INFO" "配置 SSH 公钥认证"
    
    local ssh_dir="$HOME/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"
    
    # 创建 .ssh 目录
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        print_status "SUCCESS" ".ssh 目录已创建"
    fi
    
    read -rp "$(echo -e "${WHITE}[?]${NC} SSH 公钥（单行）: ")" public_key
    
    if [[ -z "$public_key" ]]; then
        print_status "ERROR" "公钥不能为空"
        return 1
    fi
    
    if ! validate_ssh_public_key "$public_key"; then
        print_status "ERROR" "无效或不支持的 SSH 公钥"
        return 1
    fi
    
    # 检查重复
    if [[ -f "$auth_keys" ]] && grep -Fq "$public_key" "$auth_keys"; then
        print_status "WARNING" "该公钥已存在"
        return 0
    fi
    
    # 添加公钥
    echo "$public_key" >> "$auth_keys"
    chmod 600 "$auth_keys"
    sudo chown "$SCRIPT_USER:$(id -gn)" "$auth_keys"
    
    local key_count
    key_count=$(grep -c '^ssh-' "$auth_keys" 2>/dev/null || echo "0")
    print_status "SUCCESS" "公钥已添加，共有 $key_count 个有效密钥"
}

# 16. 显示 SSH 主机密钥指纹
show_ssh_fingerprints() {
    echo -e "\n${WHITE}===============================${NC}"
    echo -e "${WHITE}     SSH 主机密钥指纹        ${NC}"
    echo -e "${WHITE}===============================${NC}"
    
    local host_keys=("/etc/ssh/ssh_host_"*"_key.pub")
    local found_keys=0
    
    for key_file in "${host_keys[@]}"; do
        if [[ -f "$key_file" ]]; then
            found_keys=1
            local key_type
            key_type=$(awk '{print $1}' "$key_file" 2>/dev/null)
            local sha256_fp
            sha256_fp=$(ssh-keygen -lf "$key_file" 2>/dev/null | awk '{print $2}')
            
            echo -e "\n${CYAN}类型:${NC} $key_type"
            echo -e "${CYAN}SHA256:${NC} $sha256_fp"
            echo "-------------------------------"
        fi
    done
    
    if [[ $found_keys -eq 0 ]]; then
        print_status "ERROR" "未找到 SSH 主机密钥文件"
        return 1
    fi
    
    print_status "SUCCESS" "SSH 主机密钥指纹显示完成"
}

# 4. 创建自定义用户
create_custom_user() {
    print_status "PROGRESS" "创建自定义用户"
    
    read -rp "$(echo -e "${WHITE}[?]${NC} 用户名 (小写，首字母为字母或下划线，最大32字符): ")" new_user
    if [[ -z "$new_user" ]]; then
        print_status "ERROR" "用户名不能为空"
        return 1
    fi
    if ! [[ "$new_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        print_status "ERROR" "用户名格式无效"
        return 1
    fi
    if id -u "$new_user" &>/dev/null; then
        print_status "ERROR" "用户 $new_user 已存在"
        return 1
    fi

    # 创建用户并 home
    sudo useradd -m -s /bin/bash "$new_user"
    check_result $? "用户 $new_user 创建成功" "用户创建失败" || return 1

    local new_user_home new_user_group
    new_user_home=$(getent passwd "$new_user" | cut -d: -f6)
    new_user_group=$(id -gn "$new_user" 2>/dev/null)
    if [[ -z "$new_user_home" || -z "$new_user_group" ]]; then
        print_status "ERROR" "无法获取 $new_user 的 home 或主组"
        return 1
    fi

    # 设置密码（可留空以禁用密码登录）
    read -rsp "$(echo -e "${WHITE}[?]${NC} 为 $new_user 设置密码（留空则不设置密码，回车跳过）: ")" passwd_input
    echo
    if [[ -n "$passwd_input" ]]; then
        echo "$new_user:$passwd_input" | sudo chpasswd
        check_result $? "用户 $new_user 密码已设置" "设置密码失败" || return 1
    else
        print_status "SKIP" "未为 $new_user 设置密码（建议使用 SSH 公钥登录）"
    fi

    if prompt_user "是否将 $new_user 添加到 $ADMIN_GROUP (sudo) 组?"; then
        sudo usermod -aG "$ADMIN_GROUP" "$new_user"
        check_result $? "已将 $new_user 添加到 $ADMIN_GROUP 组" "加入管理员组失败" || return 1
    fi

    # 选择是否创建无密码 sudoers
    # if prompt_user "是否为 $new_user 创建免密码 sudoers"; then
    #     echo "$new_user ALL=(ALL) NOPASSWD:ALL" | sudo tee "/etc/sudoers.d/$new_user" >/dev/null
    #     sudo chmod 0440 "/etc/sudoers.d/$new_user"
    #     check_result $? "无密码 sudoers 已创建: /etc/sudoers.d/$new_user" "创建 sudoers 失败"
    # fi

    # 额外群组（逗号分隔）
    read -rp "$(echo -e "${WHITE}[?]${NC} 追加到其他群组 (逗号分隔，例如 docker,adm)，留空跳过: ")" extra_groups
    if [[ -n "$extra_groups" ]]; then
        IFS=',' read -ra GARR <<< "$extra_groups"
        for g in "${GARR[@]}"; do
            g_trimmed=$(echo "$g" | xargs)
            if [[ -z "$g_trimmed" ]]; then
                continue
            fi
            if ! getent group "$g_trimmed" &>/dev/null; then
                print_status "ERROR" "附加群组不存在: $g_trimmed"
                return 1
            fi
            sudo usermod -aG "$g_trimmed" "$new_user"
            check_result $? "" "加入群组 $g_trimmed 失败" || return 1
        done
        print_status "SUCCESS" "已将 $new_user 添加到额外群组: $extra_groups"
    fi

    # 添加 SSH 公钥（可选）
    if prompt_user "是否为 $new_user 添加 SSH 公钥?"; then
        read -rp "$(echo -e "${WHITE}[?]${NC} 请粘贴 SSH 公钥（单行）: ")" user_pubkey
        if [[ -n "$user_pubkey" ]]; then
            if ! validate_ssh_public_key "$user_pubkey"; then
                print_status "ERROR" "无效或不支持的 SSH 公钥"
                return 1
            fi
            local ssh_dir="$new_user_home/.ssh"
            local auth_keys="$ssh_dir/authorized_keys"
            if ! sudo -u "$new_user" mkdir -p "$ssh_dir" ||
               ! echo "$user_pubkey" | sudo -u "$new_user" tee -a "$auth_keys" >/dev/null ||
               ! sudo chmod 700 "$ssh_dir" ||
               ! sudo chmod 600 "$auth_keys" ||
               ! sudo chown -R "$new_user":"$new_user_group" "$ssh_dir"; then
                print_status "ERROR" "SSH 公钥配置失败"
                return 1
            fi
            print_status "SUCCESS" "SSH 公钥已添加到 $auth_keys"
        else
            print_status "WARNING" "未提供公钥，跳过"
        fi
    fi

    print_status "SUCCESS" "自定义用户 $new_user 创建完成"
}

# 17. 启用 journald 持久化日志
enable_journald_persistence() {
    print_status "PROGRESS" "配置 systemd-journald 持久化日志"

    local journald_dropin_dir="/etc/systemd/journald.conf.d"
    local journald_persistent_conf="$journald_dropin_dir/80-persistent.conf"

    if ! sudo mkdir -p "$journald_dropin_dir"; then
        print_status "ERROR" "创建 journald 配置目录失败: $journald_dropin_dir"
        return 1
    fi

    if ! sudo tee "$journald_persistent_conf" >/dev/null <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=2G
SystemKeepFree=1G
MaxRetentionSec=30day
EOF
    then
        print_status "ERROR" "写入 journald 持久化配置失败: $journald_persistent_conf"
        return 1
    fi
    print_status "SUCCESS" "journald 持久化配置已写入: $journald_persistent_conf"

    print_status "PROGRESS" "重启 systemd-journald 并刷新当前日志"
    if ! sudo systemctl restart systemd-journald; then
        print_status "ERROR" "systemd-journald 重启失败"
        return 1
    fi

    if ! sudo journalctl --flush; then
        print_status "ERROR" "journalctl --flush 执行失败"
        return 1
    fi

    print_status "PROGRESS" "验证 journald 配置是否已被 systemd 读取"
    local loaded_journald_config
    if ! loaded_journald_config=$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null); then
        print_status "ERROR" "无法通过 systemd-analyze 读取 journald 合并配置"
        return 1
    fi

    local required_journald_settings=(
        "Storage=persistent"
        "SystemMaxUse=2G"
        "SystemKeepFree=1G"
        "MaxRetentionSec=30day"
    )
    local missing_setting=0
    local setting
    for setting in "${required_journald_settings[@]}"; do
        local effective_value
        effective_value=$(get_journald_setting "${setting%%=*}" <<< "$loaded_journald_config")
        if [[ "$effective_value" == "${setting#*=}" ]]; then
            print_status "SUCCESS" "配置已生效: $setting"
        else
            print_status "ERROR" "配置未生效: $setting（当前: ${effective_value:-未设置}）"
            missing_setting=1
        fi
    done
    if [[ $missing_setting -ne 0 ]]; then
        return 1
    fi

    print_status "PROGRESS" "验证 /var/log/journal 下是否已有持久化 journal 文件"
    if [[ ! -d /var/log/journal ]]; then
        print_status "ERROR" "未检测到持久化日志目录: /var/log/journal"
        return 1
    fi

    local persistent_journal_file
    persistent_journal_file=$(sudo find /var/log/journal -maxdepth 2 -type f -name '*.journal*' -print -quit 2>/dev/null)
    if [[ -z "$persistent_journal_file" ]]; then
        print_status "ERROR" "未检测到 /var/log/journal 下的 .journal 文件"
        return 1
    fi

    print_status "SUCCESS" "已检测到持久化 journal 文件: $persistent_journal_file"
    sudo ls -ld /var/log/journal 2>/dev/null || true
    sudo find /var/log/journal -maxdepth 2 -type f -name '*.journal*' -ls 2>/dev/null | head -20 || true
    sudo journalctl --disk-usage 2>/dev/null || true
    print_status "SUCCESS" "当前 boot 的 journal 已写入 /var/log/journal"
    print_status "INFO" "无需重启可验证当前落盘；历史 boot 仍需重启后用 journalctl --list-boots 验证"
}

# 显示菜单
show_menu() {
    clear
    echo -e "${WHITE}=== ${PRETTY_NAME:-Linux} 初始化脚本 ===${NC}"
    
    local menu_items=(
        "设置代理"
        "修改主机名"
        "关闭 SELinux"
        "创建自定义用户"
        "配置 SSH"
        "安装基础软件包"
        "安装 ZSH 工具链"
        "同步系统时间"
        "启用 TCP BBR"
        "配置 Swap（文件 / zram）"
        "设置自动更新"
        "配置 AIDE 定期检查"
        "Lynis 安全审计"
        "安装 Docker"
        "配置 SSH 公钥"
        "显示 SSH 主机密钥指纹"
        "启用 journald 持久化日志"
    )
    
    for i in {1..17}; do
        if is_executed "$i"; then
            local exec_time
            exec_time=$(get_execution_time "$i" | cut -c 6-16)
            printf "${GREEN}%2d. %-30s ✓ [%s]${NC}\n" "$i" "${menu_items[$((i-1))]}" "$exec_time"
        else
            printf "%2d. %-30s\n" "$i" "${menu_items[$((i-1))]}"
        fi
    done
    
    echo -e "\n18. 查看执行日志"
    echo "19. 系统检查"
    echo "0.  退出"
    echo -e "${WHITE}==================================${NC}"
    echo -e "${CYAN}日志文件: $LOG_FILE${NC}"
    echo -e "${WHITE}==================================${NC}"
}

# 查看执行日志
view_logs() {
    echo -e "${WHITE}最近 20 条日志:${NC}"
    echo "=================================="
    if [[ -f "$LOG_FILE" ]]; then
        tail -20 "$LOG_FILE"
    else
        print_status "WARNING" "日志文件不存在: $LOG_FILE"
    fi
    echo "=================================="
    read -rp "按回车键返回菜单..."
}

# 主程序
main() {


    # 初始化检查
    check_os
    
    # 首次运行时自动执行预检查
    if [[ ! -f "$CONFIG_FILE" ]] || [[ ! -s "$CONFIG_FILE" ]]; then
        pre_check
        echo ""
        read -rp "$(echo -e "${WHITE}[?]${NC} 按回车键继续...")"
    fi
    
    while true; do
        show_menu
        if ! read -rp "$(echo -e "${WHITE}[?]${NC} 请选择操作 (0-19): ")" choice; then
            print_status "WARNING" "输入结束，已退出"
            exit 0
        fi
        
        case "$choice" in
            1) run_menu_item "1" "设置代理" setup_proxy ;;
            2) run_menu_item "2" "修改主机名" change_hostname ;;
            3) run_menu_item "3" "关闭 SELinux" disable_selinux ;;
            4) run_menu_item "4" "创建自定义用户" create_custom_user ;;
            5) run_menu_item "5" "配置 SSH" configure_ssh ;;
            6) run_menu_item "6" "安装基础软件包" install_basic_packages ;;
            7) run_menu_item "7" "安装 ZSH 工具链" install_zsh_tools ;;
            8) run_menu_item "8" "同步系统时间" sync_system_time ;;
            9) run_menu_item "9" "启用 TCP BBR" enable_bbr ;;
            10) run_menu_item "10" "配置 Swap" configure_swap ;;
            11) run_menu_item "11" "设置自动更新" setup_auto_updates ;;
            12) run_menu_item "12" "配置 AIDE" configure_aide ;;
            13) run_menu_item "13" "Lynis 安全审计" run_lynis_audit ;;
            14) run_menu_item "14" "安装 Docker" install_docker ;;
            15) run_menu_item "15" "配置 SSH 公钥" configure_ssh_keys ;;
            16) run_menu_item "16" "显示 SSH 主机密钥指纹" show_ssh_fingerprints ;;
            17) run_menu_item "17" "启用 journald 持久化日志" enable_journald_persistence ;;
            18) run_menu_item "18" "查看执行日志" view_logs ;;
            19) run_menu_item "19" "系统检查" pre_check ;;
            0) 
                print_status "INFO" "用户退出脚本"
                echo -e "${GREEN}[+] 感谢使用！${NC}"
                exit 0
                ;;
            *)
                print_status "WARNING" "无效选择，请输入 0-19"
                sleep 1
                ;;
        esac
        
        if [[ "$choice" -ge 1 && "$choice" -le 17 ]] || [[ "$choice" -eq 19 ]]; then
            echo ""
            read -rp "$(echo -e "${WHITE}[?]${NC} 按回车键返回菜单...")"
        fi
    done
}

# 脚本入口
if [[ $# -gt 0 ]]; then
    check_os
    if [[ "$1" != "check_os" ]]; then
        "$@"
    fi
else
    main
fi
