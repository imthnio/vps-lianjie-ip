# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，查看每个来源 IP 的运营商、城市、近24小时 / 近7天流量和最近活动时间。后台每 120 秒采样，开机自启。

## 安装（root）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "yum install -y" "dnf install -y"; do b=${pm%% *}; c $b || continue; [ $b = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-lianjie-ip/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-lianjie-ip@main/install.sh; do (wget -qO /tmp/liuliang-install.sh "$u" || curl -fsSL -o /tmp/liuliang-install.sh "$u") 2>/dev/null && [ -s /tmp/liuliang-install.sh ] && head -1 /tmp/liuliang-install.sh | grep -q "^#!/bin/sh" && { ok=1; break; }; rm -f /tmp/liuliang-install.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/liuliang-install.sh'
```

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)
