# 初始化脚本

## 使用方式

1. 引导ISO文件，在引导过程中，选择 `Install Rocky Linux`，并按下 Tab键。
从 vmlinuz 开始的引导行将出现在屏幕底部。输入 “Tab” 键后，删除 quiet
字符串，然后添加以下内容：
```
inst.ks=https://raw.githubusercontent.com/wzhone/init/master/anaconda-ks.cfg net.ifnames=0 biosdevname=0
```
然后回车开始安装系统。

2. 在服务器上执行以下命令。
```bash
curl https://raw.githubusercontent.com/wzhone/init/master/init.sh | bash 
```

## 注意事项

* 避免使用root用户执行初始化脚本