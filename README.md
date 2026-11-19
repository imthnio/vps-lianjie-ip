# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，直观查看每个连接的**端口**、**来源 IP**、**所在城市**以及**近 24 小时 / 近 7 天流量**（按流量从高到低排序；加 `--wide` 可查看运营商与最近活动时间）。后台每 60 秒采样，开机自启。

表格里输入序号（或 `liuliang --ip IP`），查看这个 IP 近7天访问的应用/网站和各自用的流量（读取 Xray / V2Ray / sing-box / Hysteria2 的访问日志，只记域名，不记网址和内容）。
看不到访问的网站时，表格里会提示原因并问你要不要现在打开（直接回车就打开，代理会重启几秒，输入 `n` 跳过）；也可以直接运行 `liuliang --enable-log` 自动打开代理的访问记录。

表格里还有「端口」栏，显示这个 IP 最近7天连过哪些节点端口（后台更新后，从新产生的连接开始记；hy2/tuic 这类 UDP 节点也一样）。

## 屏蔽某个 IP

表格里看到不想显示的 IP（比如自己的服务器）：表格下面输入 `b 序号`（如 `b 3`）屏蔽，`u 序号` 解除屏蔽。也可以直接运行：

```sh
liuliang --block 1.2.3.4        # 屏蔽一个 IP
liuliang --block 1.2.3.0/24     # 屏蔽整个网段
liuliang --unblock 1.2.3.4      # 解除屏蔽
liuliang --blocked              # 查看屏蔽名单
```

屏蔽只管显示：以后 `liuliang` 表格里不再显示这些 IP、也不计入合计，`liuliang --all` 可以查看（标 `[封]`）。实际连接不受影响，重启、更新后名单都在。

## 安装（root）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "yum install -y" "dnf install -y"; do b=${pm%% *}; c $b || continue; [ $b = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-lianjie-ip/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-lianjie-ip@main/install.sh; do (wget -qO /tmp/liuliang-install.sh "$u" || curl -fsSL -o /tmp/liuliang-install.sh "$u") 2>/dev/null && [ -s /tmp/liuliang-install.sh ] && head -1 /tmp/liuliang-install.sh | grep -q "^#!/bin/sh" && { ok=1; break; }; rm -f /tmp/liuliang-install.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/liuliang-install.sh'
```

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)
