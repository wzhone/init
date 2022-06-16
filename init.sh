#!/bin/bash

# SSH
sed -i "s/#Port 22/Port 50000/g" /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
firewall-cmd --add-port=50000/tcp --permanent

# Common
dnf install -y epel-release tmux elrepo-release tar chrony git rsync iptables* telnet tree net-tools
dnf install -y p7zip python39 neovim wget zsh util-linux-user lynis netcat yum-utils
dnf install -y python39-pip python39-devel unzip lrzsz s3fs-fuse firewalld rpcbind nfs-utils
dnf update -y
pip3 install glances bottle
systemctl enable firewalld
systemctl enable sshd

# ZSH
sh -c "$(wget https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"
echo "alias glances='/usr/local/bin/glances -t 0.5'" >> /etc/zshrc  
echo "alias dunow='du -hl --max-depth=1'" >> /etc/zshrc
echo "alias html='cd /var/www/html'" >> /etc/zshrc  
echo "alias rs='sudo systemctl restart'" >> /etc/zshrc  
echo "alias st='systemctl status'" >> /etc/zshrc  
echo "alias up='sudo -i'" >> /etc/zshrc  
echo "alias mv='mv -i'" >> /etc/zshrc  
echo "alias rm='rm -i'" >> /etc/zshrc  
echo "alias vim='nvim'" >> /etc/zshrc  
chsh -s /bin/zsh root

# FZF
git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
~/.fzf/install --all

# Add super user
useradd wzh
echo "wzh ALL=(ALL)  NOPASSWD:ALL" >> /etc/sudoers

# Upgrade Kernel
dnf --disablerepo=\* --enablerepo=elrepo-kernel install -y kernel-ml.x86_64
rpm -qa | grep kernel

# Other
sed -i 's/enforcing/disabled/' /etc/selinux/config
setenforce 0

sed -i 's/2.pool.ntp.org/time.windows.com/' /etc/chrony.conf
systemctl enable --now chronyd 
sleep 2s


# BBR
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p


# -----END-----
echo "------------------------------------"
echo "时间同步状态："
chronyc sources 
echo "BBR 状态:"
lsmod | grep bbr

echo "重启后请执行 after.sh"
echo "ssh服务端口将使用50000 端口"
echo "请手动重启"
echo "------------------------------------"
