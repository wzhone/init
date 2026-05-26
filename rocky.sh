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
readonly LOG_FILE="$LOG_DIR/rocky-init.log"
readonly CONFIG_FILE="$LOG_DIR/rocky-init.conf"

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

    local version_major="${VERSION_ID%%.*}"
    local pretty_name="${PRETTY_NAME:-$ID $VERSION_ID}"
    case "$ID" in
        rocky|almalinux)
            if [[ ! "$version_major" =~ ^(8|9|10)$ ]]; then
                print_status "ERROR" "不支持的系统版本: $pretty_name"
                exit 1
            fi
            ;;
        ol)
            if [[ ! "$version_major" =~ ^(8|9)$ ]]; then
                print_status "ERROR" "不支持的系统版本: $pretty_name"
                exit 1
            fi
            ;;
        centos)
            if [[ "${PRETTY_NAME:-$NAME}" != *"Stream"* ]] || [[ ! "$version_major" =~ ^(9|10)$ ]]; then
                print_status "ERROR" "仅支持 CentOS Stream 9/10，不支持当前系统: $pretty_name"
                exit 1
            fi
            ;;
        *)
            print_status "ERROR" "此脚本仅支持 Rocky/AlmaLinux/Oracle Linux/CentOS Stream，当前系统: $pretty_name"
            exit 1
            ;;
    esac

    print_status "INFO" "操作系统检查通过: $pretty_name"
}

# 用户确认函数
prompt_user() {
    local prompt="$1"
    local default="${2:-Y}"
    
    while true; do
        read -rp "$(echo -e "${WHITE}[?]${NC} $prompt (${default,,}/n): ")" response
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
    ss -tuln | grep -q ":$port "
}

# 配置防火墙端口
configure_firewall_port() {
    local port=$1
    
    if command -v firewall-cmd &>/dev/null; then
        print_status "PROGRESS" "配置防火墙端口 $port"
        if sudo firewall-cmd --add-port="$port"/tcp --permanent &>/dev/null && \
           sudo firewall-cmd --reload &>/dev/null; then
            print_status "SUCCESS" "端口 $port 已开放"
            return 0
        else
            print_status "ERROR" "防火墙配置失败"
            return 1
        fi
    else
        print_status "ERROR" "未检测到防火墙服务，无法保证新端口可用"
        return 1
    fi
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

    local service
    for service in sshd chronyd docker dnf-automatic.timer systemd-journald; do
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

    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Eq '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*persistent[[:space:]]*$' && \
       sudo find /var/log/journal -maxdepth 2 -type f -name '*.journal*' -print -quit 2>/dev/null | grep -q .; then
        print_status "SUCCESS" "journald: 已持久化写入 /var/log/journal"
    else
        print_status "INFO" "journald: 未确认持久化写入"
    fi

    if [[ -f /var/lib/aide/aide.db.gz ]]; then
        print_status "SUCCESS" "AIDE: 数据库已存在"
    else
        print_status "INFO" "AIDE: 未检测到数据库"
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
    
    if ! prompt_user "确认要关闭 SELinux 吗？"; then
        print_status "SKIP" "SELinux 保持当前状态"
        return 77
    fi
    
    print_status "PROGRESS" "禁用 SELinux"
    
    sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config &>/dev/null
    sudo setenforce 0 &>/dev/null
    
    print_status "SUCCESS" "SELinux 已禁用（重启后生效）"
}

# 5. 配置 SSH
configure_ssh() {
    print_status "PROGRESS" "配置 SSH 安全设置"
    
    # 获取用户输入的SSH端口
    local ssh_port=""
    while true; do
        read -rp "$(echo -e "${WHITE}[?]${NC} SSH 端口号 (1024-65535，默认 2222): ")" ssh_port
        ssh_port=${ssh_port:-2222}
        
        # 验证端口号
        if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || [[ $ssh_port -lt 1024 ]] || [[ $ssh_port -gt 65535 ]]; then
            print_status "ERROR" "端口号无效，请输入 1024-65535 之间的数字"
            continue
        fi
        
        # 检查端口占用
        if check_port "$ssh_port"; then
            print_status "WARNING" "端口 $ssh_port 已被占用"
            if ! prompt_user "是否继续使用此端口"; then
                continue
            fi
        fi
        
        break
    done
    
    print_status "INFO" "使用 SSH 端口: $ssh_port"
    
    # 安装必要组件
    sudo dnf install -y policycoreutils-python-utils
    check_result $? "" "SELinux 工具安装失败"
    
    # 备份配置
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_config_backup
    ssh_config_backup="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
    if ! sudo cp "$ssh_config" "$ssh_config_backup"; then
        print_status "ERROR" "sshd_config 备份失败，已终止"
        return 1
    fi
    
    # SELinux 端口配置
    if [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        if ! command -v semanage &>/dev/null; then
            print_status "ERROR" "未找到 semanage，无法配置 SELinux 端口"
            return 1
        fi
        if sudo semanage port -l 2>/dev/null | grep -qE "^ssh_port_t.*\\b${ssh_port}\\b"; then
            print_status "INFO" "SELinux 端口策略已存在: $ssh_port"
        else
            if sudo semanage port -a -t ssh_port_t -p tcp "$ssh_port" &>/dev/null; then
                print_status "SUCCESS" "SELinux 端口策略已配置"
            else
                print_status "ERROR" "SELinux 端口策略配置失败"
                return 1
            fi
        fi
    fi
    
    # 让用户选择是否禁止 root 登录，并在没有其它可登录用户时给出明确警告
    local permit_root_choice="yes"
    if prompt_user "是否禁止 root 通过 SSH 登录（推荐）? 提示：如果系统上没有第二个可登录用户，禁止 root 登录 会导致无法远程进入 (风险很大)"; then
        # 用户选择禁止 root 登录 -> 但先检查是否存在非 system 的可登录用户
        local other_user
        other_user=$(awk -F: '($3>=1000)&&($7!~/(nologin|false)/){print $1; exit}' /etc/passwd 2>/dev/null || true)
        if [[ -z "$other_user" ]]; then
            print_status "WARNING" "未检测到 UID>=1000 且 shell 非 nologin/false 的普通用户。禁止 root 登录 可能导致远程被锁定。"
            if ! prompt_user "仍然继续禁止 root 登录？"; then
                permit_root_choice="yes"
            else
                permit_root_choice="no"
            fi
        else
            permit_root_choice="no"
        fi
    else
        # 用户选择不禁止 root 登录
        permit_root_choice="yes"
    fi

    # 防火墙放行（失败则不改 sshd_config）
    if ! configure_firewall_port "$ssh_port"; then
        print_status "ERROR" "防火墙端口配置失败，已终止 SSH 端口变更"
        return 1
    fi

    # ssh 配置更新 (确保对现有配置行做替换/追加)
    # Port
    if sudo grep -q -E '^Port ' "$ssh_config"; then
        sudo sed -i -E "s/^#?Port .*/Port $ssh_port/" "$ssh_config"
    else
        echo "Port $ssh_port" | sudo tee -a "$ssh_config" >/dev/null
    fi
    # PermitEmptyPasswords
    if sudo grep -q -E '^PermitEmptyPasswords ' "$ssh_config"; then
        sudo sed -i -E 's/^#?PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$ssh_config"
    else
        echo "PermitEmptyPasswords no" | sudo tee -a "$ssh_config" >/dev/null
    fi
    # PermitRootLogin 根据选择设置
    if [[ "$permit_root_choice" == "no" ]]; then
        if sudo grep -q -E '^PermitRootLogin ' "$ssh_config"; then
            sudo sed -i -E 's/^#?PermitRootLogin .*/PermitRootLogin no/' "$ssh_config"
        else
            echo "PermitRootLogin no" | sudo tee -a "$ssh_config" >/dev/null
        fi
        print_status "INFO" "已设置 PermitRootLogin no（禁止 root 登录）"
    else
        if sudo grep -q -E '^PermitRootLogin ' "$ssh_config"; then
            sudo sed -i -E 's/^#?PermitRootLogin .*/PermitRootLogin yes/' "$ssh_config"
        else
            echo "PermitRootLogin yes" | sudo tee -a "$ssh_config" >/dev/null
        fi
        print_status "INFO" "保持 PermitRootLogin yes（允许 root 登录）"
    fi

    # 其余连接控制配置
    if sudo grep -q -E '^ClientAliveInterval ' "$ssh_config"; then
        sudo sed -i -E 's/^#?ClientAliveInterval .*/ClientAliveInterval 30/' "$ssh_config"
    else
        echo "ClientAliveInterval 30" | sudo tee -a "$ssh_config" >/dev/null
    fi
    if sudo grep -q -E '^ClientAliveCountMax ' "$ssh_config"; then
        sudo sed -i -E 's/^#?ClientAliveCountMax .*/ClientAliveCountMax 2/' "$ssh_config"
    else
        echo "ClientAliveCountMax 2" | sudo tee -a "$ssh_config" >/dev/null
    fi

    # Fail2ban 配置
    if prompt_user "安装 fail2ban 防护"; then
        print_status "PROGRESS" "配置 fail2ban"
        sudo dnf install -y epel-release fail2ban &>/dev/null
        
        sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $ssh_port
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
        sudo systemctl enable --now fail2ban &>/dev/null
        print_status "SUCCESS" "fail2ban 已配置 (端口: $ssh_port)"
    fi
    
    # 重启前校验配置
    if ! sudo sshd -t -f "$ssh_config" &>/dev/null; then
        print_status "ERROR" "sshd_config 校验失败，已回滚"
        sudo cp "$ssh_config_backup" "$ssh_config" &>/dev/null || true
        return 1
    fi

    # 重启 SSH 服务
    if sudo systemctl restart sshd &>/dev/null; then
        print_status "SUCCESS" "SSH 配置完成，端口: $ssh_port"
    else
        print_status "ERROR" "SSH 服务重启失败，尝试回滚配置"
        sudo cp "$ssh_config_backup" "$ssh_config" &>/dev/null || true
        sudo systemctl restart sshd &>/dev/null || true
        return 1
    fi
}

# 6. 安装基础软件包
install_basic_packages() {
    print_status "PROGRESS" "安装基础软件包"
    
    local packages=(
        "tar" "git" "rsync" "telnet" "tree" "net-tools"
        "p7zip" "vim" "lrzsz" "wget" "netcat" "yum-utils" "util-linux-user"
        "htop" "iotop" "iftop" "nload" "sysstat" "dstat" "ncdu" "tmux"
    )
    
    sudo dnf update -y
    sudo dnf install -y epel-release
    sudo dnf install -y "${packages[@]}"
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
    
    # 检查依赖
    for cmd in git curl; do
        if ! command -v "$cmd" &>/dev/null; then
            sudo dnf install -y "$cmd" &>/dev/null
            check_result $? "$cmd 安装完成" "$cmd 安装失败" || return 1
        fi
    done
    
    # 安装 ZSH
    sudo dnf install -y zsh
    check_result $? "ZSH 安装完成" "ZSH 安装失败" || return 1
    
    # 更改默认 shell
    sudo chsh -s "$(command -v zsh)" "$zsh_user"
    check_result $? "$zsh_user 的默认 shell 已更改为 ZSH" "默认 shell 更改失败" || return 1
    
    # 安装 Oh My Zsh
    if [[ ! -d "$zsh_home/.oh-my-zsh" ]]; then
        print_status "PROGRESS" "安装 Oh My Zsh"
        sudo -u "$zsh_user" env HOME="$zsh_home" RUNZSH=no CHSH=no KEEP_ZSHRC=yes \
            sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
        check_result $? "Oh My Zsh 安装完成" "Oh My Zsh 安装失败" || return 1
    fi
    
    local zsh_custom="$zsh_home/.oh-my-zsh/custom"
    sudo -u "$zsh_user" mkdir -p "$zsh_custom/themes" "$zsh_custom/plugins"
    
    # 安装 Powerlevel10k 主题
    if [[ ! -d "$zsh_custom/themes/powerlevel10k" ]]; then
        print_status "PROGRESS" "安装 Powerlevel10k 主题"
        sudo -u "$zsh_user" env HOME="$zsh_home" \
            git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$zsh_custom/themes/powerlevel10k"
        check_result $? "Powerlevel10k 主题安装完成" "主题安装失败" || return 1
    fi
    
    # 修改 .zshrc 配置文件
    print_status "PROGRESS" "配置 ZSH 设置"
    local zshrc="$zsh_home/.zshrc"
    if [[ ! -f "$zshrc" ]]; then
        sudo -u "$zsh_user" touch "$zshrc"
    fi
    
    # 修改主题设置
    if sudo grep -q '^ZSH_THEME=' "$zshrc"; then
        sudo sed -i 's|^ZSH_THEME=.*|ZSH_THEME="powerlevel10k/powerlevel10k"|' "$zshrc"
    else
        echo 'ZSH_THEME="powerlevel10k/powerlevel10k"' | sudo tee -a "$zshrc" >/dev/null
    fi
    check_result $? "ZSH 主题配置完成" "ZSH 主题配置失败" || return 1
    
    # 修改插件设置
    if sudo grep -q '^plugins=' "$zshrc"; then
        sudo sed -i 's/^plugins=.*/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/' "$zshrc"
    else
        echo 'plugins=(git zsh-syntax-highlighting zsh-autosuggestions)' | sudo tee -a "$zshrc" >/dev/null
    fi
    check_result $? "ZSH 插件配置完成" "ZSH 插件配置失败" || return 1
    
    # 添加自定义 alias 到 .zshrc 末尾
    if ! sudo grep -q '# 自定义 alias' "$zshrc"; then
        sudo tee -a "$zshrc" >/dev/null << 'EOF'

# 自定义 alias
alias dunow='du -hl --max-depth=1'
alias rs='sudo systemctl restart'
alias st='sudo systemctl status'
alias systemctl='sudo systemctl'
alias docker='sudo docker'
alias cat='sudo cat'
alias dnf='sudo dnf'
alias tail='sudo tail'
alias mv='mv -i'
alias rm='rm -i'

# 减少更新提醒
export UPDATE_ZSH_DAYS=365
EOF
        check_result $? "自定义 alias 添加完成" "alias 配置失败" || return 1
    else
        print_status "INFO" "自定义 alias 已存在，跳过追加"
    fi

    # 安装插件
    local plugins=(
        "zsh-autosuggestions|https://github.com/zsh-users/zsh-autosuggestions"
        "zsh-syntax-highlighting|https://github.com/zsh-users/zsh-syntax-highlighting"
    )
    
    for plugin_info in "${plugins[@]}"; do
        local plugin_name="${plugin_info%|*}"
        local plugin_url="${plugin_info#*|}"
        local plugin_dir="$zsh_custom/plugins/$plugin_name"
        
        if [[ ! -d "$plugin_dir" ]]; then
            print_status "PROGRESS" "安装 $plugin_name 插件"
            sudo -u "$zsh_user" env HOME="$zsh_home" git clone --depth=1 "$plugin_url" "$plugin_dir"
            check_result $? "$plugin_name 插件安装完成" "$plugin_name 插件安装失败" || return 1
        fi
    done
    
    # 安装 FZF
    if [[ ! -d "$zsh_home/.fzf" ]]; then
        print_status "PROGRESS" "安装 FZF"
        sudo -u "$zsh_user" env HOME="$zsh_home" git clone --depth 1 https://github.com/junegunn/fzf.git "$zsh_home/.fzf"
        check_result $? "FZF 下载完成" "FZF 下载失败" || return 1
        sudo -u "$zsh_user" env HOME="$zsh_home" "$zsh_home/.fzf/install" --all
        check_result $? "FZF 安装完成" "FZF 安装失败" || return 1
    fi

    sudo chown -R "$zsh_user":"$(id -gn "$zsh_user")" "$zsh_home/.oh-my-zsh" "$zsh_home/.zshrc" "$zsh_home/.fzf" 2>/dev/null || true
    
    print_status "SUCCESS" "ZSH 工具链已为 $zsh_user 安装完成，请重新登录应用更改"
}

# 8. 同步系统时间
sync_system_time() {
    print_status "PROGRESS" "配置时间同步"
    
    sudo dnf install -y chrony &>/dev/null
    check_result $? "Chrony 安装完成" "Chrony 安装失败" || return 1
    
    # 配置时间服务器
    local chrony_conf="/etc/chrony.conf"
    sudo cp "$chrony_conf" "${chrony_conf}.bak"
    
    # 注释默认服务器并添加新的
    sudo sed -i 's/^server/#server/' "$chrony_conf"
    
    local time_servers=(
        "pool.ntp.org"
        "time.windows.com"
        "time.nist.gov"
        "time.google.com"
    )
    
    for server in "${time_servers[@]}"; do
        echo "server $server iburst" | sudo tee -a "$chrony_conf" >/dev/null
    done
    
    sudo systemctl enable --now chronyd &>/dev/null
    check_result $? "时间同步服务已启用" "时间同步配置失败"
    
    sleep 2
    sudo chronyc sources 2>/dev/null | head -5
}

# 9. 启用 TCP BBR
enable_bbr() {
    print_status "PROGRESS" "启用 BBR 拥塞控制"
    
    local sysctl_conf="/etc/sysctl.conf"
    local bbr_config=(
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    
    for config in "${bbr_config[@]}"; do
        if ! grep -q "$config" "$sysctl_conf"; then
            echo "$config" | sudo tee -a "$sysctl_conf" >/dev/null
        fi
    done
    
    if ! sudo sysctl -p &>/dev/null; then
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

# 10. 创建 Swap
configure_swap() {
    print_status "PROGRESS" "配置 Swap"

    if awk 'NR > 1 {found=1} END {exit found ? 0 : 1}' /proc/swaps 2>/dev/null; then
        print_status "SUCCESS" "检测到已有 Swap，跳过创建"
        swapon --show 2>/dev/null || cat /proc/swaps
        return 0
    fi

    if ! command -v mkswap &>/dev/null || ! command -v swapon &>/dev/null; then
        sudo dnf install -y util-linux
        check_result $? "Swap 工具安装完成" "Swap 工具安装失败" || return 1
    fi

    local swap_size_gb
    while true; do
        read -rp "$(echo -e "${WHITE}[?]${NC} Swap 大小（单位 G，默认 4）: ")" swap_size_gb
        swap_size_gb=${swap_size_gb:-4}
        if [[ "$swap_size_gb" =~ ^[1-9][0-9]*$ ]]; then
            break
        fi
        print_status "WARNING" "请输入正整数，例如 2 或 4"
    done

    local swap_file="/swapfile"
    if sudo test -e "$swap_file"; then
        print_status "WARNING" "$swap_file 已存在"
        if ! prompt_user "是否删除后重新创建"; then
            print_status "SKIP" "已跳过 Swap 创建"
            return 77
        fi
        sudo swapoff "$swap_file" 2>/dev/null || true
        if ! sudo rm -f "$swap_file"; then
            print_status "ERROR" "删除旧 swapfile 失败: $swap_file"
            return 1
        fi
    fi

    print_status "PROGRESS" "创建 ${swap_size_gb}G swapfile"
    if ! {
        if command -v fallocate &>/dev/null; then
            sudo fallocate -l "${swap_size_gb}G" "$swap_file" 2>/dev/null || \
                sudo dd if=/dev/zero of="$swap_file" bs=1M count=$((swap_size_gb * 1024))
        else
            sudo dd if=/dev/zero of="$swap_file" bs=1M count=$((swap_size_gb * 1024))
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
    if ! sudo grep -Eq '^[[:space:]]*/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0' /etc/fstab; then
        echo "$fstab_entry" | sudo tee -a /etc/fstab >/dev/null
    fi

    print_status "SUCCESS" "Swap 已创建并启用: ${swap_size_gb}G"
    swapon --show 2>/dev/null || cat /proc/swaps
}

# 11. 设置自动安全更新
setup_auto_updates() {
    print_status "PROGRESS" "配置自动安全更新"
    
    sudo dnf install -y dnf-automatic
    check_result $? "DNF automatic 安装完成" "安装失败" || return 1
    
    sudo sed -i 's/apply_updates = no/apply_updates = yes/g' /etc/dnf/automatic.conf
    sudo systemctl enable --now dnf-automatic.timer
    
    sleep 2
    if systemctl is-active --quiet dnf-automatic.timer; then
        print_status "SUCCESS" "自动更新已配置"
    else
        print_status "ERROR" "自动更新配置失败"
        return 1
    fi
}

# 12. 配置 AIDE
configure_aide() {
    print_status "PROGRESS" "安装文件完整性检测工具"
    
    sudo dnf install -y aide
    check_result $? "AIDE 安装完成" "AIDE 安装失败" || return 1
    
    print_status "PROGRESS" "初始化 AIDE 数据库（可能需要几分钟）"
    if ! sudo aide --init; then
        print_status "ERROR" "AIDE 数据库初始化失败"
        return 1
    fi

    local aide_new_db="/var/lib/aide/aide.db.new.gz"
    local aide_db="/var/lib/aide/aide.db.gz"
    if ! sudo test -f "$aide_new_db"; then
        print_status "ERROR" "未找到 AIDE 初始化生成的数据库: $aide_new_db"
        return 1
    fi

    if ! sudo mv "$aide_new_db" "$aide_db"; then
        print_status "ERROR" "AIDE 数据库启用失败: $aide_db"
        return 1
    fi
    
    print_status "SUCCESS" "AIDE 配置完成"
}

# 13. 系统安全审计
security_audit() {
    print_status "PROGRESS" "执行系统安全审计"
    
    sudo dnf install -y lynis rkhunter 
    
    print_status "PROGRESS" "运行 Lynis 安全扫描"
    sudo lynis audit system --quiet
    print_status "SUCCESS" "Lynis 审计完成，日志: /var/log/lynis.log"
    
    print_status "PROGRESS" "运行 RKHunter 扫描"
    sudo rkhunter --update --quiet 
    sudo rkhunter --check --skip-keypress --quiet
    print_status "SUCCESS" "RKHunter 审计完成，日志: /var/log/rkhunter/rkhunter.log"
}

# 14. 安装 Docker
install_docker() {
    print_status "PROGRESS" "安装 Docker CE"
    
    sudo dnf install -y yum-utils &>/dev/null
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo &>/dev/null
    sudo dnf install -y docker-ce docker-ce-cli containerd.io
    check_result $? "Docker 安装完成" "Docker 安装失败" || return 1
    
    sudo systemctl enable --now docker &>/dev/null
    sudo usermod -aG docker "$SCRIPT_USER"
    
    print_status "SUCCESS" "Docker 已安装，请重新登录应用用户组更改"
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
    
    read -rp "$(echo -e "${WHITE}[?]${NC} SSH 公钥 (格式: ssh-rsa AAAAB3...): ")" public_key
    
    if [[ -z "$public_key" ]]; then
        print_status "ERROR" "公钥不能为空"
        return 1
    fi
    
    # 验证公钥格式
    if [[ ! "$public_key" =~ ^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp(256|384|521))\ [A-Za-z0-9+/]+ ]]; then
        print_status "ERROR" "无效的公钥格式"
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
            local md5_fp
            md5_fp=$(ssh-keygen -lf "$key_file" -E md5 2>/dev/null | awk '{print $2}')
            
            echo -e "\n${CYAN}类型:${NC} $key_type"
            echo -e "${CYAN}SHA256:${NC} $sha256_fp"
            echo -e "${CYAN}MD5:${NC} $md5_fp"
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

    # 设置密码（可留空以禁用密码登录）
    read -rsp "$(echo -e "${WHITE}[?]${NC} 为 $new_user 设置密码（留空则不设置密码，回车跳过）: ")" passwd_input
    echo
    if [[ -n "$passwd_input" ]]; then
        echo "$new_user:$passwd_input" | sudo chpasswd
        check_result $? "用户 $new_user 密码已设置" "设置密码失败"
    else
        print_status "SKIP" "未为 $new_user 设置密码（建议使用 SSH 公钥登录）"
    fi

    # 选择是否加入 wheel（sudo）组
    if prompt_user "是否将 $new_user 添加到 wheel (sudo) 组?"; then
        sudo usermod -aG wheel "$new_user"
        check_result $? "已将 $new_user 添加到 wheel 组" "加入 wheel 组失败"
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
                sudo groupadd "$g_trimmed"
            fi
            sudo usermod -aG "$g_trimmed" "$new_user"
        done
        print_status "SUCCESS" "已将 $new_user 添加到额外群组: $extra_groups"
    fi

    # 添加 SSH 公钥（可选）
    if prompt_user "是否为 $new_user 添加 SSH 公钥?"; then
        read -rp "$(echo -e "${WHITE}[?]${NC} 请粘贴 SSH 公钥（单行）: ")" user_pubkey
        if [[ -n "$user_pubkey" ]]; then
            sudo -u "$new_user" mkdir -p "/home/$new_user/.ssh"
            echo "$user_pubkey" | sudo -u "$new_user" tee -a "/home/$new_user/.ssh/authorized_keys" >/dev/null
            sudo chmod 700 "/home/$new_user/.ssh"
            sudo chmod 600 "/home/$new_user/.ssh/authorized_keys"
            sudo chown -R "$new_user":"$new_user" "/home/$new_user/.ssh"
            print_status "SUCCESS" "SSH 公钥已添加到 /home/$new_user/.ssh/authorized_keys"
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
    local journald_persistent_conf="$journald_dropin_dir/10-persistent.conf"

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
        if grep -Eq "^[[:space:]]*${setting%%=*}[[:space:]]*=[[:space:]]*${setting#*=}[[:space:]]*$" <<< "$loaded_journald_config"; then
            print_status "SUCCESS" "配置已读取: $setting"
        else
            print_status "ERROR" "配置未读取: $setting"
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
    echo -e "${WHITE}==================================${NC}"
    echo -e "${WHITE}  Rocky Linux 系统初始化脚本   ${NC}"
    echo -e "${WHITE}==================================${NC}"
    
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
        "创建 Swap"
        "设置自动安全更新"
        "配置 AIDE"
        "系统安全审计"
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
            10) run_menu_item "10" "创建 Swap" configure_swap ;;
            11) run_menu_item "11" "设置自动安全更新" setup_auto_updates ;;
            12) run_menu_item "12" "配置 AIDE" configure_aide ;;
            13) run_menu_item "13" "系统安全审计" security_audit ;;
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
    "$@"
else
    main
fi
