# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，查看每个来源 IP 的运营商、城市、近24小时 / 近7天流量和最近活动时间。后台每 120 秒采样，开机自启。

## 安装（root，一行）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "yum install -y" "dnf install -y"; do b=${pm%% *}; c $b || continue; [ $b = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-lianjie-ip/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-lianjie-ip@main/install.sh; do (wget -qO /tmp/liuliang-install.sh "$u" || curl -fsSL -o /tmp/liuliang-install.sh "$u") 2>/dev/null && [ -s /tmp/liuliang-install.sh ] && head -1 /tmp/liuliang-install.sh | grep -q "^#!/bin/sh" && { ok=1; break; }; rm -f /tmp/liuliang-install.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/liuliang-install.sh'
```

一行搞定：自动识别 curl / wget，两个都没有就自动装；install.sh 从 GitHub 和 jsdelivr 双镜像下载。

全自动安装，全程无需任何操作：自动检测代理监听端口（TCP+UDP，hy2 这类纯 UDP 端口也能认出来）和其他对外服务端口（比如文件传输网站；NAT VPS 取内部监听端口）。已经装过的机器重跑会自动并入新检测到的端口，原有端口和流量记录保留。

已经装过的机器再执行一次上面的命令会更新程序。原来的流量记录和端口配置都还在。

装好后产生一点流量，约两分钟后运行 `liuliang` 查看。

归属地（运营商 / 城市）是 IP 估计值，仅供参考。

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)
