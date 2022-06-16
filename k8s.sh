#!/bin/bash

# 安装K8S
dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
exclude=kubelet kubeadm kubectl
EOF
dnf install -y kubelet kubeadm kubectl --disableexcludes=kubernetes
dnf install -y yum-utils device-mapper-persistent-data lvm2 containerd.io


# 准备配置文件
containerd config default > /etc/containerd/config.toml
sed -i "s/SystemdCgroup = false/SystemdCgroup = true/" /etc/containerd/config.toml
echo "KUBELET_EXTRA_ARGS=--container-runtime=remote --container-runtime-endpoint=/run/containerd/containerd.sock --cgroup-driver=systemd" > /etc/sysconfig/kubelet

crictl config \
	--set runtime-endpoint=unix:///run/containerd/containerd.sock \
	--set image-endpoint=unix:///run/containerd/containerd.sock



# 启用系统相关的 
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-arptables=1
net.ipv4.tcp_tw_recycle=0
net.ipv4.tcp_tw_reuse=0
net.core.somaxconn=32768
net.netfilter.nf_conntrack_max=1000000
vm.swappiness=0
vm.max_map_count=655360
fs.file-max=6553600
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=10
EOF

cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
nf_conntrack
nf_conntrack_ipv4
br_netfilter
overlay
EOF

# 添加防火墙规则 
firewall-cmd --permanent --new-service=k8s
firewall-cmd --service=k8s --permanent --add-port=6443/tcp # Kubernetes API server
firewall-cmd --service=k8s --permanent --add-port=2379-2380/tcp # etcd server client API
firewall-cmd --service=k8s --permanent --add-port=10250/tcp # Kubelet API
firewall-cmd --service=k8s --permanent --add-port=10251/tcp # kube-scheduler
firewall-cmd --service=k8s --permanent --add-port=10252/tcp # kube-controller-manager
firewall-cmd --service=k8s --permanent --add-port=8285/udp # Flannel
firewall-cmd --service=k8s --permanent --add-port=8472/udp # Flannel
firewall-cmd --add-masquerade --permanent
firewall-cmd --service=k8s --permanent --add-port=30000-32767/tcp
firewall-cmd --service=k8s --reload
firewall-cmd --add-service=k8s --permanent
firewall-cmd --reload

# 重启相应服务
sysctl -p
sysctl --system
systemctl enable --now containerd 
systemctl enable --now kubelet
systemctl daemon-reload

echo "---------通用命令结束---------"

# 初始化控制面节点
# kubeadm init --pod-network-cidr=10.244.0.0/16 --ignore-preflight-errors=all 
# echo "export KUBECONFIG=/etc/kubernetes/admin.conf" >> /root/.zshrc
# kubectl apply -f https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml
