#!/bin/bash
dnf remove -y kernel-4.18.0 kernel-core-4.18.0 kernel-modules-4.18.0 kernel-devel-4.18.0 kernel-tools-4.18.0 ker nel-tools-libs-4.18.0 kernel-headers-4.18.0

git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
sed -i "s/robbyrussell/powerlevel10k\/powerlevel10k/g" /etc/ssh/sshd_config
curl https://raw.githubusercontent.com/wzhone/init/master/p10k.zsh -o /root/.p10k.zsh
