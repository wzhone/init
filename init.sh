#!/bin/bash

# 函数：提示用户确认
prompt_user() {
    while true; do
        read -p "$1 (Y/n): " yn
        case $yn in
        [Yy]* | '') return 0 ;;
        [Nn]*) return 1 ;;
        *) echo "请输入 Y 或 n." ;;
        esac
    done
}

# 检测操作系统并设置相应的包管理器和命令
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
else
    echo "无法检测操作系统类型。"
    exit 1
fi

# 初始化变量
INSTALL_CMD=""
UPDATE_CMD=""
ENABLE_SERVICE_CMD=""
GITHUB_URL_PREFIX=""

case $OS in
ubuntu)
    INSTALL_CMD="apt install -y"
    UPDATE_CMD="apt update -y && apt upgrade -y"
    ENABLE_SERVICE_CMD="systemctl enable --now"
    ;;
arch)
    INSTALL_CMD="pacman -S --noconfirm"
    UPDATE_CMD="pacman -Syu --noconfirm"
    ENABLE_SERVICE_CMD="systemctl enable --now"
    ;;
rocky)
    INSTALL_CMD="dnf install -y"
    UPDATE_CMD="dnf update -y"
    ENABLE_SERVICE_CMD="systemctl enable --now"
    ;;
*)
    echo "不支持的操作系统：$OS"
    exit 1
    ;;
esac

# 询问是否使用 GitHub 代理
USE_GITHUB_PROXY=0
if prompt_user "需要使用 GitHub 代理加速？"; then
    USE_GITHUB_PROXY=1
    GITHUB_URL_PREFIX="https://ghp.ci/"
else
    GITHUB_URL_PREFIX=""
fi

# 1. 修改主机名
if prompt_user "是否需要修改当前设备名称"; then
    read -p "请输入新的主机名: " NEW_HOSTNAME
    if [ -n "$NEW_HOSTNAME" ]; then
        hostnamectl set-hostname "$NEW_HOSTNAME"
        echo "主机名已修改为 $NEW_HOSTNAME"
    else
        echo "主机名不能为空，跳过修改。"
    fi
fi

#########################
# 2. 配置 SSH
#########################
if prompt_user "是否需要配置 SSH 设置"; then
    echo "正在配置 SSH..."

    # 备份 SSH 配置文件
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # 修改默认 SSH 端口为 2222
    sed -i "s/#Port 22/Port 2222/g" /etc/ssh/sshd_config

    # 禁止空密码登录
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

    # 禁止 root 登录
    sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config

    # 设置最大认证尝试次数为 1
    sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 1/g' /etc/ssh/sshd_config

    # 设置客户端保持连接
    sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 30/g' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/g' /etc/ssh/sshd_config

    # 添加防火墙规则，允许新的 SSH 端口
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "rocky" ]; then
        if command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --add-port=2222/tcp --permanent || firewall-offline-cmd --add-port=2222/tcp
            firewall-cmd --reload
        elif command -v ufw >/dev/null 2>&1; then
            ufw allow 2222/tcp
            ufw reload
        fi
    elif [ "$OS" = "arch" ]; then
        if command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --add-port=2222/tcp --permanent || firewall-offline-cmd --add-port=2222/tcp
            firewall-cmd --reload
        fi
    fi

    # 重启 SSH 服务
    $ENABLE_SERVICE_CMD sshd

    echo "SSH 配置完成。"
fi

#########################
# 3. 安装基础软件包
#########################
if prompt_user "是否需要安装基础软件包"; then
    echo "正在安装基础软件包..."

    if [ "$OS" = "ubuntu" ]; then
        $INSTALL_CMD software-properties-common
        $UPDATE_CMD
        $INSTALL_CMD tmux tar git rsync telnet tree net-tools p7zip-full vim lrzsz wget netcat-openbsd fail2ban util-linux
    elif [ "$OS" = "arch" ]; then
        $INSTALL_CMD base-devel tmux tar git rsync telnet tree net-tools p7zip vim lrzsz wget netcat fail2ban util-linux
    elif [ "$OS" = "rocky" ]; then
        $INSTALL_CMD epel-release
        $INSTALL_CMD tmux tar git rsync telnet tree net-tools p7zip vim lrzsz wget netcat yum-utils fail2ban util-linux-user
        $UPDATE_CMD
    fi

    echo "基础软件包安装完成。"
fi

#########################
# 4. 安装 ZSH、Powerlevel10k、FZF
#########################
if prompt_user "是否需要安装 ZSH、Powerlevel10k 主题和 FZF"; then
    echo "正在安装 ZSH 及相关工具..."

    # 安装 ZSH
    $INSTALL_CMD zsh

    # 安装 Oh My Zsh（无人值守模式）
    sh -c "$(curl -fsSL ${GITHUB_URL_PREFIX}https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

    # 更改默认 shell 为 ZSH
    chsh -s /bin/zsh $(whoami)

    # 安装 Powerlevel10k 主题
    git clone --depth=1 ${GITHUB_URL_PREFIX}https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k

    # 设置 ZSH 主题为 Powerlevel10k
    sed -i 's/ZSH_THEME=".*"/ZSH_THEME="powerlevel10k\/powerlevel10k"/g' ~/.zshrc

    # 下载 Powerlevel10k 和 ZSH 配置文件
    curl -fsSL ${GITHUB_URL_PREFIX}https://raw.githubusercontent.com/wzhone/init/master/p10k.zsh -o ~/.p10k.zsh
    curl -fsSL ${GITHUB_URL_PREFIX}https://raw.githubusercontent.com/wzhone/init/master/zshrc -o ~/.zshrc

    # 安装 FZF（命令行模糊查找器）
    git clone --depth 1 ${GITHUB_URL_PREFIX}https://github.com/junegunn/fzf.git ~/.fzf
    ~/.fzf/install --all

    echo "ZSH 及相关工具安装完成。"
fi

#########################
# 5. 关闭 SELinux（Rocky Linux）
#########################
if [ "$OS" = "rocky" ]; then
    if prompt_user "是否需要关闭 SELinux"; then
        echo "正在关闭 SELinux..."

        # 设置 SELinux 配置为 disabled 并应用
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
        setenforce 0

        echo "SELinux 已关闭。"
    fi
fi

#########################
# 6. 同步系统时间
#########################
if prompt_user "是否需要同步系统时间"; then
    echo "正在同步系统时间..."

    # 安装时间同步工具
    if [ "$OS" = "ubuntu" ]; then
        $INSTALL_CMD chrony
    elif [ "$OS" = "arch" ]; then
        $INSTALL_CMD chrony
    elif [ "$OS" = "rocky" ]; then
        $INSTALL_CMD chrony
    fi

    # 配置 NTP 服务器
    if [ -f /etc/chrony/chrony.conf ]; then
        CHRONY_CONF="/etc/chrony/chrony.conf"
    elif [ -f /etc/chrony.conf ]; then
        CHRONY_CONF="/etc/chrony.conf"
    fi

    if [ -n "$CHRONY_CONF" ]; then
        # 备份原始配置文件
        cp $CHRONY_CONF ${CHRONY_CONF}.bak

        # 使用多个 NTP 服务器
        cat >$CHRONY_CONF <<EOF
server ntp.aliyun.com iburst
server cn.pool.ntp.org iburst
server time.windows.com iburst
server ntp.ntsc.ac.cn iburst
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
# 7. 启用 TCP BBR
#########################
if prompt_user "是否需要启用BBR"; then
    echo "正在启用 BBR..."

    # 配置 sysctl 设置以启用 BBR
    echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    echo "net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf

    # 应用 sysctl 设置
    sysctl -p

    # 验证 BBR 模块是否已加载
    echo -n "BBR 状态: "
    lsmod | grep bbr

    echo "BBR 已启用。"
fi

#########################
# 8. 进行系统安全审计
#########################
if prompt_user "是否需要进行系统安全审计"; then
    echo "正在进行系统安全审计..."

    # 安装安全审计工具
    $INSTALL_CMD lynis rkhunter

    # 运行 Lynis 审计
    lynis audit system
    echo "Lynis 审计日志："
    cat /var/log/lynis.log

    # 更新并运行 RKHunter
    rkhunter --update
    rkhunter --check
    echo "RKHunter 审计日志："
    cat /var/log/rkhunter/rkhunter.log

    echo "系统安全审计完成。"
fi

#########################
# 9. 设置自动安全更新
#########################
if prompt_user "是否需要设置自动安全更新"; then
    echo "正在设置自动安全更新..."

    # 安装自动更新工具
    if [ "$OS" = "ubuntu" ]; then
        $INSTALL_CMD unattended-upgrades
        dpkg-reconfigure -plow unattended-upgrades
    elif [ "$OS" = "arch" ]; then
        echo "Arch Linux 不支持自动安全更新，建议手动定期更新。"
    elif [ "$OS" = "rocky" ]; then
        $INSTALL_CMD dnf-automatic
        sed -i 's/apply_updates = no/apply_updates = yes/g' /etc/dnf/automatic.conf
        $ENABLE_SERVICE_CMD dnf-automatic.timer
    fi

    echo "自动安全更新已设置。"
fi

#########################
# 10. 配置防火墙
#########################
if prompt_user "是否需要使用基本设置配置防火墙"; then
    echo "正在配置防火墙..."

    # 启用并启动防火墙服务
    if [ "$OS" = "ubuntu" ]; then
        $INSTALL_CMD ufw
        ufw allow 2222/tcp
        ufw enable
    elif [ "$OS" = "arch" ] || [ "$OS" = "rocky" ]; then
        $INSTALL_CMD firewalld
        $ENABLE_SERVICE_CMD firewalld
        firewall-cmd --permanent --add-port=2222/tcp
        # 可选：允许 HTTP 和 HTTPS 服务
        # firewall-cmd --permanent --add-service=http
        # firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    fi

    echo "防火墙已配置。"
fi

#########################
# 11. 安装 Docker
#########################
if prompt_user "是否需要安装 Docker"; then
    echo "正在安装 Docker..."

    if [ "$OS" = "ubuntu" ]; then
        $INSTALL_CMD apt-transport-https ca-certificates curl gnupg lsb-release
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
        add-apt-repository \
            "deb [arch=$(dpkg --print-architecture)] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) \
          stable"
        $UPDATE_CMD
        $INSTALL_CMD docker-ce docker-ce-cli containerd.io
        $ENABLE_SERVICE_CMD docker
    elif [ "$OS" = "arch" ]; then
        $INSTALL_CMD docker
        $ENABLE_SERVICE_CMD docker
    elif [ "$OS" = "rocky" ]; then
        $INSTALL_CMD yum-utils
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        $INSTALL_CMD docker-ce docker-ce-cli containerd.io
        $ENABLE_SERVICE_CMD docker
    fi

    # 将当前用户添加到 docker 组
    sudo usermod -aG docker $(whoami)

    echo "Docker 安装完成。请重新登录以应用用户组更改。"
fi

echo "初始化脚本执行完成。"