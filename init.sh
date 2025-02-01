#!/bin/bash

prompt_user() {
    while true; do
        read -rp "$1 (Y/n): " yn
        yn=${yn:-Y}  # 默认值为 'Y'
        case $yn in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "请输入 Y 或 n." ;;
        esac
    done
}

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    case $OS in
        ubuntu|debian)
            INSTALL_CMD="sudo apt install -y"
            UPDATE_CMD="apt update -y && apt upgrade -y"
            ENABLE_SERVICE_CMD="systemctl enable --now"
            ;;
        arch)
            INSTALL_CMD="sudo pacman -S --noconfirm"
            UPDATE_CMD="pacman -Syu --noconfirm"
            ENABLE_SERVICE_CMD="systemctl enable --now"
            ;;
        rocky|centos|fedora)
            INSTALL_CMD="sudo dnf install -y"
            UPDATE_CMD="dnf update -y"
            ENABLE_SERVICE_CMD="systemctl enable --now"
            ;;
        *)
            echo "不支持的操作系统：$OS"
            exit 1
            ;;
    esac
else
    echo "无法检测操作系统类型。"
    exit 1
fi

GITHUB_URL_PREFIX=""

USE_GITHUB_PROXY=0
if prompt_user "需要使用 GitHub 代理加速？"; then
    USE_GITHUB_PROXY=1
    GITHUB_URL_PREFIX="https://ghfast.top/"
else
    GITHUB_URL_PREFIX=""
fi

#########################
# 修改主机名
#########################
if prompt_user "是否需要修改当前设备名称"; then
    read -rp "请输入新的主机名: " NEW_HOSTNAME
    if [ -n "$NEW_HOSTNAME" ]; then
        hostnamectl set-hostname "$NEW_HOSTNAME"
        echo "主机名已修改为 $NEW_HOSTNAME"
    else
        echo "主机名不能为空，跳过修改。"
    fi
fi

#########################
# 关闭 SELinux（Rocky Linux）
#########################
if [ "$OS" = "rocky" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
    if prompt_user "是否停用 SELinux"; then
        echo "正在停用S SELinux..."

        # 设置 SELinux 配置为 permissive 并应用
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
        setenforce 0

        echo "SELinux 已停用。请注意，这可能降低系统安全性。"
    fi
fi



#########################
# 配置 SSH
#########################
if prompt_user "是否需要配置 SSH 设置"; then
    echo "警告：修改 SSH 配置可能会导致当前会话中断，请谨慎操作。"
    if ! prompt_user "是否继续"; then
        echo "跳过 SSH 配置。"
    else
        echo "正在配置 SSH..."

        # 备份 SSH 配置文件
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

        # 修改默认 SSH 端口为 2222
        sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config

        # 禁止空密码登录
        sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

        # 禁止 root 登录
        sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

        # 设置客户端保持连接
        sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 30/' /etc/ssh/sshd_config
        sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/' /etc/ssh/sshd_config

        # 添加防火墙规则，允许新的 SSH 端口
        if command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --add-port=2222/tcp --permanent
            firewall-cmd --reload
        elif command -v ufw >/dev/null 2>&1; then
            ufw allow 2222/tcp
            ufw reload
        else
            echo "未检测到防火墙工具，请手动配置防火墙以允许端口 2222。"
        fi

        # 重启 SSH 服务
        systemctl restart sshd

        echo "SSH 配置完成。请使用新的端口 2222 重新连接 SSH。"
    fi
fi

#########################
# 安装基础软件包
#########################
if prompt_user "是否需要安装基础软件包"; then
    echo "正在安装基础软件包..."

    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        $UPDATE_CMD
        $INSTALL_CMD software-properties-common
        $INSTALL_CMD tmux tar git rsync telnet tree net-tools p7zip-full vim lrzsz wget netcat-openbsd util-linux
    elif [ "$OS" = "arch" ]; then
        $UPDATE_CMD
        $INSTALL_CMD base-devel tmux tar git rsync telnet tree net-tools p7zip vim lrzsz wget netcat util-linux
    elif [ "$OS" = "rocky" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
        $INSTALL_CMD epel-release
        $UPDATE_CMD
        $INSTALL_CMD tmux tar git rsync telnet tree net-tools p7zip vim lrzsz wget netcat yum-utils util-linux-user
    fi

    echo "基础软件包安装完成。"
fi

#########################
# 安装 ZSH、Powerlevel10k、FZF
#########################
if prompt_user "是否需要安装 ZSH、Powerlevel10k 主题和 FZF"; then
    echo "正在安装 ZSH 及相关工具..."

    # 安装 ZSH
    $INSTALL_CMD zsh

    # 安装 Oh My Zsh（无人值守模式）
    sh -c "$(curl -fsSL ${GITHUB_URL_PREFIX}https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

    # 定义 ZSH_CUSTOM 变量
    ZSH_CUSTOM=${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}

    # 更改默认 shell 为 ZSH
    chsh -s "$(which zsh)" "$(whoami)"

    # 安装 Powerlevel10k 主题
    git clone --depth=1 ${GITHUB_URL_PREFIX}https://github.com/romkatv/powerlevel10k.git $ZSH_CUSTOM/themes/powerlevel10k

    # 下载 Powerlevel10k 和 ZSH 配置文件
    curl -fsSL ${GITHUB_URL_PREFIX}https://raw.githubusercontent.com/wzhone/init/master/p10k.zsh -o ~/.p10k.zsh
    curl -fsSL ${GITHUB_URL_PREFIX}https://raw.githubusercontent.com/wzhone/init/master/zshrc -o ~/.zshrc

    # 安装 zsh-syntax-highlighting 和 zsh-autosuggestions 插件
    git clone --depth=1 ${GITHUB_URL_PREFIX}https://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
    git clone --depth=1 ${GITHUB_URL_PREFIX}https://github.com/zsh-users/zsh-syntax-highlighting $ZSH_CUSTOM/plugins/zsh-syntax-highlighting

    # 安装 FZF（命令行模糊查找器）
    git clone --depth 1 ${GITHUB_URL_PREFIX}https://github.com/junegunn/fzf.git ~/.fzf
    ~/.fzf/install --all

    echo "ZSH 及相关工具安装完成。请重新登录以应用更改。"
fi


#########################
# 同步系统时间
#########################
if prompt_user "是否需要同步系统时间"; then
    echo "正在同步系统时间..."

    # 安装时间同步工具
    $INSTALL_CMD chrony

    # 配置 NTP 服务器
    if [ -f /etc/chrony/chrony.conf ]; then
        CHRONY_CONF="/etc/chrony/chrony.conf"
    elif [ -f /etc/chrony.conf ]; then
        CHRONY_CONF="/etc/chrony.conf"
    fi

    if [ -n "$CHRONY_CONF" ]; then
        # 备份原始配置文件
        cp $CHRONY_CONF ${CHRONY_CONF}.bak

        # 注释掉默认的 server 配置
        sed -i 's/^server/#server/' $CHRONY_CONF

        # 添加新的 NTP 服务器
        cat >>$CHRONY_CONF <<EOF
server pool.ntp.org iburst
server time.windows.com iburst
server time.nist.gov iburst
server time.apple.com iburst
server time.google.com iburst
EOF
    fi

    # 启用并启动 Chrony 服务
    $ENABLE_SERVICE_CMD chronyd

    # 显示同步状态
    echo "时间同步状态："
    chronyc sources

    echo "系统时间已同步。"
fi

#########################
# 启用 TCP BBR
#########################
if prompt_user "是否需要启用 BBR"; then
    echo "正在启用 BBR..."

    # 检查并添加配置
    grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf

    # 应用 sysctl 设置
    sysctl -p

    # 验证 BBR 模块是否已加载
    if lsmod | grep -q "bbr"; then
        echo "BBR 已成功启用。"
    else
        echo "BBR 启用失败，请检查内核版本是否支持 BBR。"
    fi
fi


#########################
# 设置自动安全更新
#########################
if prompt_user "是否需要设置自动安全更新"; then
    echo "正在设置自动安全更新..."

    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        $INSTALL_CMD unattended-upgrades
        dpkg-reconfigure -plow unattended-upgrades

        # 确保自动更新配置文件正确
        sed -i 's/^\/\/\s*"${distro_id}:${distro_codename}-updates";/"${distro_id}:${distro_codename}-updates";/' /etc/apt/apt.conf.d/50unattended-upgrades
        sed -i 's/^\/\/\s*"${distro_id}:${distro_codename}-security";/"${distro_id}:${distro_codename}-security";/' /etc/apt/apt.conf.d/50unattended-upgrades
    elif [ "$OS" = "arch" ]; then
        echo "Arch Linux 不建议自动更新整个系统。您可以使用定期提醒或手动更新。"
    elif [ "$OS" = "rocky" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
        $INSTALL_CMD dnf-automatic
        sed -i 's/apply_updates = no/apply_updates = yes/g' /etc/dnf/automatic.conf
        $ENABLE_SERVICE_CMD dnf-automatic.timer
    fi

    echo "自动安全更新已设置。"
fi

#########################
# 配置防火墙
#########################
if prompt_user "是否需要使用基本设置配置防火墙"; then
    echo "正在配置防火墙..."

    if command -v ufw >/dev/null 2>&1; then
        FIREWALL_CMD="ufw"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALL_CMD="firewall-cmd"
    else
        if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
            $INSTALL_CMD ufw
            FIREWALL_CMD="ufw"
        else
            $INSTALL_CMD firewalld
            FIREWALL_CMD="firewall-cmd"
            $ENABLE_SERVICE_CMD firewalld
        fi
    fi

    if [ "$FIREWALL_CMD" = "ufw" ]; then
        ufw allow 2222/tcp
        ufw enable
    elif [ "$FIREWALL_CMD" = "firewall-cmd" ]; then
        firewall-cmd --permanent --add-port=2222/tcp
        firewall-cmd --reload
    fi

    echo "防火墙已配置。"
fi

#########################
# 进行系统安全审计
#########################
if prompt_user "是否需要进行系统安全审计"; then
    echo "正在进行系统安全审计..."

    # 检查并安装安全审计工具
    if ! command -v lynis >/dev/null 2>&1; then
        $INSTALL_CMD lynis || echo "无法安装 Lynis，请手动安装。"
    fi

    if ! command -v rkhunter >/dev/null 2>&1; then
        $INSTALL_CMD rkhunter || echo "无法安装 RKHunter，请手动安装。"
    fi

    # 运行 Lynis 审计
    lynis audit system
    echo "Lynis 审计已完成。日志文件位于 /var/log/lynis.log。"

    # 更新并运行 RKHunter
    rkhunter --update
    rkhunter --check
    echo "RKHunter 审计已完成。日志文件位于 /var/log/rkhunter/rkhunter.log。"

    echo "系统安全审计完成。请查看日志文件获取详细信息。"
fi

#########################
# 安装 Docker
#########################
if prompt_user "是否需要安装 Docker"; then
    echo "正在安装 Docker..."

    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        $INSTALL_CMD apt-transport-https ca-certificates curl gnupg lsb-release
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
            $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        $UPDATE_CMD
        $INSTALL_CMD docker-ce docker-ce-cli containerd.io
        $ENABLE_SERVICE_CMD docker
    elif [ "$OS" = "arch" ]; then
        $INSTALL_CMD docker
        $ENABLE_SERVICE_CMD docker
    elif [ "$OS" = "rocky" ] || [ "$OS" = "centos" ] || [ "$OS" = "fedora" ]; then
        $INSTALL_CMD yum-utils
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        $INSTALL_CMD docker-ce docker-ce-cli containerd.io
        $ENABLE_SERVICE_CMD docker
    fi

    # 将当前用户添加到 docker 组
    sudo usermod -aG docker "$(whoami)"

    echo "Docker 安装完成。请重新登录以应用用户组更改。"
fi

echo "初始化脚本执行完成。"