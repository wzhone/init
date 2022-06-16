#!/bin/bash

cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

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

cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
br_netfilter
EOF

# Add firewalld rules
ffirewall-cmd --permanent --new-service=k8s
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

systemctl restart firewalld

dnf install -y kubelet kubeadm kubectl --disableexcludes=kubernetes

systemctl enable docker
systemctl daemon-reload
systemctl restart docker
systemctl restart containerd
sysctl --system
systemctl enable --now kubelet

systemctl enable kubelet

kubeadm init --pod-network-cidr=10.244.0.0/16 --ignore-preflight-errors=all 


