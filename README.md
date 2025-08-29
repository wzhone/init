# Rocky Linux 系统初始化脚本

一键配置 Rocky Linux 服务器的安全和开发环境。

## 快速开始

```bash
bash <(curl -s https://raw.githubusercontent.com/wzhone/init/master/init.sh)
```

## 系统要求

- Rocky Linux 8/9/10
- sudo 权限
- 网络连接

## 主要功能

1. 代理设置
2. 主机名修改
3. SELinux 管理
4. SSH 安全配置（自定义端口）
5. 基础软件包安装
6. ZSH 工具链
7. 系统时间同步
8. TCP BBR 启用
9. 自动安全更新
10. AIDE 文件完整性检测
11. 系统安全审计
12. Docker 安装
13. SSH 公钥配置
14. SSH 主机密钥指纹显示

## 使用说明

脚本采用交互式菜单

## 日志文件

- 执行日志：`/tmp/rocky-init.log`
- 配置记录：`/tmp/rocky-init.conf`
