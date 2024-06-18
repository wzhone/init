#!/bin/bash

# 配置 SSH
sed -i "s/#Port 22/Port 2222/g" /etc/ssh/sshd_config # 修改默认端口
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config # 禁止空密码登录
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config # 禁止root用户直接登录
sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 1/g' /etc/ssh/sshd_config # 设置最大认证尝试次数为1
sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 30/g' /etc/ssh/sshd_config # 客户端连接的活跃间隔为30秒
sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/g' /etc/ssh/sshd_config # 客户端连接的最大活跃次数为2
firewall-cmd --add-port=2222/tcp --permanent || firewall-offline-cmd --add-port=2222/tcp
systemctl enable --now sshd

# 安装基础应用包
dnf install -y epel-release
dnf install -y tmux tar git rsync telnet tree net-tools p7zip vim lrzsz wget netcat yum-utils fail2ban util-linux-user
dnf update -y

# 安装不是很常用的包
dnf install -y lynis expect python3-pip python3-devel unzip rpcbind nfs-utils
pip3 install glances bottle

# 安装 ZSH P10K FZF
dnf install -y zsh 
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
chsh -s /bin/zsh `whoami`

git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
sed -i "s/robbyrussell/powerlevel10k\/powerlevel10k/g" ~/.zshrc

curl https://raw.githubusercontent.com/wzhone/init/master/p10k.zsh -o ~/.p10k.zsh
curl https://raw.githubusercontent.com/wzhone/init/master/zshrc -o ~/.zshrc

git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
~/.fzf/install --all

# 关闭SELinux
sed -i 's/enforcing/disabled/' /etc/selinux/config
setenforce 0

# 同步系统时间
dnf install -y chrony
sed -i 's/2.pool.ntp.org/time.windows.com/' /etc/chrony.conf
systemctl enable --now chronyd
echo "时间同步状态："
chronyc sources

# 启用BBR
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
echo -n "BBR 状态: "
lsmod | grep bbr

# 系统审计
dnf install -y lynis rkhunter
lynis audit system
cat /var/log/lynis.log
rkhunter --update
rkhunter --check
cat /var/log/rkhunter/rkhunter.log
