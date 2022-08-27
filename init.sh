#!/bin/bash

# SSH
sed -i "s/#Port 22/Port 50000/g" /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 2/g' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 30/g' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/g' /etc/ssh/sshd_config
firewall-cmd --add-port=50000/tcp --permanent || firewall-offline-cmd --add-port=50000/tcp


# Common
dnf install -y epel-release tmux elrepo-release tar chrony git rsync telnet tree net-tools 
dnf install -y p7zip neovim wget zsh util-linux-user lynis netcat yum-utils fail2ban expect
dnf install -y python3-pip python3-devel unzip lrzsz firewalld rpcbind nfs-utils
dnf update -y

pip3 install glances bottle

# Add super user
useradd wzh
echo "wzh ALL=(ALL)  NOPASSWD:ALL" >> /etc/sudoers
pwd=`mkpasswd-expect`
echo $pwd | passwd wzh --stdin
echo "sudo -i" >> /home/wzh/.bashrc


# ZSH
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
chsh -s /bin/zsh root

# P10K
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
sed -i "s/robbyrussell/powerlevel10k\/powerlevel10k/g" /root/.zshrc

curl https://raw.githubusercontent.com/wzhone/init/master/p10k.zsh -o /root/.p10k.zsh
curl https://raw.githubusercontent.com/wzhone/init/master/zshrc -o /root/.zshrc

# FZF
git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
~/.fzf/install --all

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

systemctl enable firewalld
systemctl enable sshd

# -----END-----
echo "------------------------------------" > /root/init.log
echo "时间同步状态：" >> /root/init.log
chronyc sources >> /root/init.log
echo -n "BBR 状态: " >> /root/init.log
lsmod | grep bbr >> /root/init.log
echo "用户密码 $pwd" >> /root/init.log
echo "------------------------------------" >> /root/init.log
