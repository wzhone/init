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
readonly LOG_DIR="/tmp"
readonly LOG_FILE="$LOG_DIR/rocky-init.log"
readonly CONFIG_FILE="$LOG_DIR/rocky-init.conf"
readonly SCRIPT_USER=$(whoami)

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
touch "$LOG_FILE" "$CONFIG_FILE" 2>/dev/null

# 统一输出函数
print_status() {
    local level="$1"
    local message="$2"
    local timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"
    
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
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    if is_executed "$item_number"; then
        local temp_file=$(mktemp)
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

# 检查操作系统
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_status "ERROR" "无法检测操作系统类型"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "rocky" ]]; then
        print_status "ERROR" "此脚本仅支持 Rocky Linux，当前系统: $ID"
        exit 1
    fi
    print_status "INFO" "操作系统检查通过: Rocky Linux $VERSION_ID"
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
        else
            print_status "WARNING" "防火墙配置可能失败"
        fi
    else
        print_status "WARNING" "未检测到防火墙服务"
    fi
}

# 预检查函数
pre_check() {
    print_status "INFO" "执行系统预检查"
    
    # 检查 sudo 权限
    print_status "PROGRESS" "检查 sudo 权限"
    if sudo -n true 2>/dev/null; then
        print_status "SUCCESS" "sudo 权限检查通过"
    else
        if sudo true 2>/dev/null; then
            print_status "SUCCESS" "sudo 权限验证成功"
        else
            print_status "WARNING" "当前用户没有 sudo 权限，部分功能可能无法使用"
        fi
    fi
    
    # 检查网络连接
    print_status "PROGRESS" "检查网络连接"
    if ping -c 1 -W 5 8.8.8.8 &>/dev/null || ping -c 1 -W 5 223.5.5.5 &>/dev/null; then
        print_status "SUCCESS" "网络连接正常"
    else
        print_status "WARNING" "网络连接异常，可能影响软件包安装"
    fi
    
    # 检查硬盘空间
    print_status "PROGRESS" "检查硬盘剩余空间"
    local available_space=$(df / | awk 'NR==2 {print int($4/1024)}')
    local available_gb=$((available_space / 1024))
    
    if [[ $available_space -gt 1048576 ]]; then  # 1GB = 1048576 KB
        print_status "SUCCESS" "硬盘剩余空间: ${available_gb}GB (充足)"
    else
        print_status "WARNING" "硬盘剩余空间不足 1GB (当前: ${available_space}MB)，可能影响软件安装"
    fi
    
    echo ""
    read -rp "$(echo -e "${WHITE}[?]${NC} 按回车键继续...")"
}

# 1. 设置代理
setup_proxy() {
    record_execution "1" "设置代理"
    print_status "INFO" "配置 HTTP 代理"

    read -rp "$(echo -e "${WHITE}[?]${NC} 代理地址 (host:port，留空跳过): ")" proxy_address

    if [[ -z "$proxy_address" ]]; then
        print_status "SKIP" "代理设置已跳过"
        return 0
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
    record_execution "2" "修改主机名"
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
    record_execution "3" "关闭 SELinux"
    
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
        return 0
    fi
    
    print_status "PROGRESS" "禁用 SELinux"
    
    sudo sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config &>/dev/null
    sudo setenforce 0 &>/dev/null
    
    print_status "SUCCESS" "SELinux 已禁用（重启后生效）"
}

# 4. 配置 SSH
configure_ssh() {
    record_execution "4" "配置 SSH"
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
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # SELinux 端口配置
    if [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        sudo semanage port -a -t ssh_port_t -p tcp "$ssh_port" &>/dev/null || \
        sudo semanage port -m -t ssh_port_t -p tcp "$ssh_port" &>/dev/null
        print_status "SUCCESS" "SELinux 端口策略已配置"
    fi
    
    # SSH 配置更新
    local ssh_config="/etc/ssh/sshd_config"
    sudo sed -i -E "s/^#?Port .*/Port $ssh_port/" "$ssh_config"
    sudo sed -i -E 's/^#?PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$ssh_config"
    sudo sed -i -E 's/^#?PermitRootLogin .*/PermitRootLogin no/' "$ssh_config"
    sudo sed -i -E 's/^#?ClientAliveInterval .*/ClientAliveInterval 30/' "$ssh_config"
    sudo sed -i -E 's/^#?ClientAliveCountMax .*/ClientAliveCountMax 2/' "$ssh_config"
    
    configure_firewall_port "$ssh_port"
    
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
    
    # 重启 SSH 服务
    sudo systemctl restart sshd
    check_result $? "SSH 配置完成，端口: $ssh_port" "SSH 服务重启失败"
}

# 5. 安装基础软件包
install_basic_packages() {
    record_execution "5" "安装基础软件包"
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

# 6. 安装 ZSH 工具链
install_zsh_tools() {
    record_execution "6" "安装 ZSH 工具链"
    print_status "PROGRESS" "安装 ZSH 和相关工具"
    
    # 检查依赖
    for cmd in git curl; do
        if ! command -v "$cmd" &>/dev/null; then
            sudo dnf install -y "$cmd" &>/dev/null
            check_result $? "$cmd 安装完成" "$cmd 安装失败"
        fi
    done
    
    # 安装 ZSH
    sudo dnf install -y zsh
    check_result $? "ZSH 安装完成" "ZSH 安装失败" || return 1
    
    # 更改默认 shell
    sudo chsh -s "$(which zsh)" "$SCRIPT_USER"
    print_status "SUCCESS" "默认 shell 已更改为 ZSH"
    
    # 安装 Oh My Zsh
    if [[ ! -d "$HOME/.oh-my-zsh" ]]; then
        print_status "PROGRESS" "安装 Oh My Zsh"
        sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
        check_result $? "Oh My Zsh 安装完成" "Oh My Zsh 安装失败"
    fi
    
    ZSH_CUSTOM="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"
    
    # 安装 Powerlevel10k 主题
    if [[ ! -d "$ZSH_CUSTOM/themes/powerlevel10k" ]]; then
        print_status "PROGRESS" "安装 Powerlevel10k 主题"
        git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$ZSH_CUSTOM/themes/powerlevel10k"
        check_result $? "Powerlevel10k 主题安装完成" "主题安装失败"
    fi
    
    # 修改 .zshrc 配置文件
    print_status "PROGRESS" "配置 ZSH 设置"
    
    # 修改主题设置
    sed -i 's/^ZSH_THEME="robbyrussell"$/ZSH_THEME="powerlevel10k\/powerlevel10k"/' "$HOME/.zshrc"
    check_result $? "ZSH 主题配置完成" "ZSH 主题配置失败"
    
    # 修改插件设置
    sed -i 's/^plugins=(git)$/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/' "$HOME/.zshrc"
    check_result $? "ZSH 插件配置完成" "ZSH 插件配置失败"
    
    # 添加自定义 alias 到 .zshrc 末尾
    cat >> "$HOME/.zshrc" << 'EOF'

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
    check_result $? "自定义 alias 添加完成" "alias 配置失败"

    # 安装插件
    local plugins=(
        "zsh-autosuggestions|https://github.com/zsh-users/zsh-autosuggestions"
        "zsh-syntax-highlighting|https://github.com/zsh-users/zsh-syntax-highlighting"
    )
    
    for plugin_info in "${plugins[@]}"; do
        local plugin_name="${plugin_info%|*}"
        local plugin_url="${plugin_info#*|}"
        local plugin_dir="$ZSH_CUSTOM/plugins/$plugin_name"
        
        if [[ ! -d "$plugin_dir" ]]; then
            print_status "PROGRESS" "安装 $plugin_name 插件"
            git clone --depth=1 "$plugin_url" "$plugin_dir"
            check_result $? "$plugin_name 插件安装完成" "$plugin_name 插件安装失败"
        fi
    done
    
    # 安装 FZF
    if [[ ! -d "$HOME/.fzf" ]]; then
        print_status "PROGRESS" "安装 FZF"
        git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
        ~/.fzf/install --all
        check_result $? "FZF 安装完成" "FZF 安装失败"
    fi
    
    print_status "SUCCESS" "ZSH 工具链安装完成，请重新登录应用更改"
}

# 7. 同步系统时间
sync_system_time() {
    record_execution "7" "同步系统时间"
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
    chronyc sources 2>/dev/null | head -5
}

# 8. 启用 TCP BBR
enable_bbr() {
    record_execution "8" "启用 TCP BBR"
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
    
    sudo sysctl -p &>/dev/null
    
    if lsmod | grep -q "tcp_bbr"; then
        print_status "SUCCESS" "BBR 已启用"
    else
        print_status "WARNING" "BBR 启用失败，请检查内核版本"
    fi
}

# 9. 设置自动安全更新
setup_auto_updates() {
    record_execution "9" "设置自动安全更新"
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
    fi
}

# 10. 配置 AIDE
configure_aide() {
    record_execution "10" "配置 AIDE"
    print_status "PROGRESS" "安装文件完整性检测工具"
    
    sudo dnf install -y aide
    check_result $? "AIDE 安装完成" "AIDE 安装失败" || return 1
    
    print_status "PROGRESS" "初始化 AIDE 数据库（可能需要几分钟）"
    sudo aide --init
    sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    
    print_status "SUCCESS" "AIDE 配置完成"
}

# 11. 系统安全审计
security_audit() {
    record_execution "11" "系统安全审计"
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

# 12. 安装 Docker
install_docker() {
    record_execution "12" "安装 Docker"
    print_status "PROGRESS" "安装 Docker CE"
    
    sudo dnf install -y yum-utils &>/dev/null
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo &>/dev/null
    sudo dnf install -y docker-ce docker-ce-cli containerd.io
    check_result $? "Docker 安装完成" "Docker 安装失败" || return 1
    
    sudo systemctl enable --now docker &>/dev/null
    sudo usermod -aG docker "$SCRIPT_USER"
    
    print_status "SUCCESS" "Docker 已安装，请重新登录应用用户组更改"
}

# 13. 配置 SSH 公钥
configure_ssh_keys() {
    record_execution "13" "配置 SSH 公钥"
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
    chown "$SCRIPT_USER:$(id -gn)" "$auth_keys"
    
    local key_count=$(grep -c '^ssh-' "$auth_keys" 2>/dev/null || echo "0")
    print_status "SUCCESS" "公钥已添加，共有 $key_count 个有效密钥"
}

# 14. 显示 SSH 主机密钥指纹
show_ssh_fingerprints() {
    record_execution "14" "显示 SSH 主机密钥指纹"
    
    echo -e "\n${WHITE}===============================${NC}"
    echo -e "${WHITE}     SSH 主机密钥指纹        ${NC}"
    echo -e "${WHITE}===============================${NC}"
    
    local host_keys=("/etc/ssh/ssh_host_"*"_key.pub")
    local found_keys=0
    
    for key_file in "${host_keys[@]}"; do
        if [[ -f "$key_file" ]]; then
            found_keys=1
            local key_type=$(awk '{print $1}' "$key_file" 2>/dev/null)
            local sha256_fp=$(ssh-keygen -lf "$key_file" 2>/dev/null | awk '{print $2}')
            local md5_fp=$(ssh-keygen -lf "$key_file" -E md5 2>/dev/null | awk '{print $2}')
            
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
        "配置 SSH"
        "安装基础软件包"
        "安装 ZSH 工具链"
        "同步系统时间"
        "启用 TCP BBR"
        "设置自动安全更新"
        "配置 AIDE"
        "系统安全审计"
        "安装 Docker"
        "配置 SSH 公钥"
        "显示 SSH 主机密钥指纹"
    )
    
    for i in {1..14}; do
        if is_executed "$i"; then
            local exec_time=$(get_execution_time "$i" | cut -c 6-16)
            printf "${GREEN}%2d. %-30s ✓ [%s]${NC}\n" "$i" "${menu_items[$((i-1))]}" "$exec_time"
        else
            printf "%2d. %-30s\n" "$i" "${menu_items[$((i-1))]}"
        fi
    done
    
    echo -e "\n15. 查看执行日志"
    echo "16. 系统预检查"
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
    # 检查用户权限
    if [[ $EUID -eq 0 ]]; then
        print_status "WARNING" "建议使用普通用户运行此脚本"
    fi
    
    # 初始化检查
    check_os
    
    # 首次运行时自动执行预检查
    if [[ ! -f "$CONFIG_FILE" ]] || [[ ! -s "$CONFIG_FILE" ]]; then
        print_status "INFO" "首次运行，执行系统预检查"
        pre_check
    fi
    
    while true; do
        show_menu
        read -rp "$(echo -e "${WHITE}[?]${NC} 请选择操作 (0-16): ")" choice
        
        case "$choice" in
            1) setup_proxy ;;
            2) change_hostname ;;
            3) disable_selinux ;;
            4) configure_ssh ;;
            5) install_basic_packages ;;
            6) install_zsh_tools ;;
            7) sync_system_time ;;
            8) enable_bbr ;;
            9) setup_auto_updates ;;
            10) configure_aide ;;
            11) security_audit ;;
            12) install_docker ;;
            13) configure_ssh_keys ;;
            14) show_ssh_fingerprints ;;
            15) view_logs ;;
            16) pre_check ;;
            0) 
                print_status "INFO" "用户退出脚本"
                echo -e "${GREEN}[+] 感谢使用！${NC}"
                exit 0
                ;;
            *)
                print_status "WARNING" "无效选择，请输入 0-16"
                sleep 1
                ;;
        esac
        
        if [[ "$choice" -ge 1 && "$choice" -le 14 ]] || [[ "$choice" -eq 16 ]]; then
            echo ""
            read -rp "$(echo -e "${WHITE}[?]${NC} 按回车键返回菜单...")"
        fi
    done
}

# 脚本入口
main "$@"