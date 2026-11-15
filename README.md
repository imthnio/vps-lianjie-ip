# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，查看每个来源 IP 的运营商、城市、近24小时 / 近7天流量和最近活动时间。后台每 60 秒采样，开机自启。

表格里输入序号（或 `liuliang --ip IP`），查看这个 IP 近7天访问的应用/网站和各自用的流量（读取 Xray / V2Ray / sing-box / Hysteria2 的访问日志，只记域名，不记网址和内容）。
看不到访问的网站时，运行 `liuliang --enable-log` 自动打开代理的访问记录。

表格里还有「端口」栏，显示这个 IP 最近7天连过哪些节点端口（后台更新后，从新产生的连接开始记）。

## 屏蔽某个 IP

表格里看到不想让它用的 IP：表格下面输入 `b 序号`（如 `b 3`）屏蔽，`u 序号` 解除屏蔽。也可以直接运行：

```sh
liuliang --block 1.2.3.4        # 屏蔽一个 IP
liuliang --block 1.2.3.0/24     # 屏蔽整个网段
liuliang --unblock 1.2.3.4      # 解除屏蔽
liuliang --blocked              # 查看屏蔽名单
```

屏蔽只拦节点端口，SSH 不受影响；重启机器后自动恢复。被屏蔽的 IP 在表格里标 `[封]`。

## 安装（root）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "yum install -y" "dnf install -y"; do b=${pm%% *}; c $b || continue; [ $b = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-lianjie-ip/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-lianjie-ip@main/install.sh; do (wget -qO /tmp/liuliang-install.sh "$u" || curl -fsSL -o /tmp/liuliang-install.sh "$u") 2>/dev/null && [ -s /tmp/liuliang-install.sh ] && head -1 /tmp/liuliang-install.sh | grep -q "^#!/bin/sh" && { ok=1; break; }; rm -f /tmp/liuliang-install.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/liuliang-install.sh'
```

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)
