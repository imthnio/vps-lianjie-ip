# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，查看每个来源 IP 的运营商、城市、近24小时 / 近7天流量和最近活动时间。后台每 120 秒采样，开机自启。

## 安装（root）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "yum install -y" "dnf install -y"; do b=${pm%% *}; c $b || continue; [ $b = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-lianjie-ip/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-lianjie-ip@main/install.sh; do (wget -qO /tmp/liuliang-install.sh "$u" || curl -fsSL -o /tmp/liuliang-install.sh "$u") 2>/dev/null && [ -s /tmp/liuliang-install.sh ] && head -1 /tmp/liuliang-install.sh | grep -q "^#!/bin/sh" && { ok=1; break; }; rm -f /tmp/liuliang-install.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/liuliang-install.sh'
```

一行搞定：自动识别 curl / wget，两个都没有就自动装；install.sh 从 GitHub 和 jsdelivr 双镜像下载。

全自动安装，全程无需任何操作：自动检测代理监听端口（TCP+UDP，hy2 这类纯 UDP 端口也能认出来）和其他对外服务端口（比如文件传输网站；NAT VPS 取内部监听端口）。已经装过的机器重跑会自动并入新检测到的端口，原有端口和流量记录保留。

已经装过的机器再执行一次 `sh install.sh` 会更新程序。原来的流量记录和端口配置都还在。

装好后产生一点流量，约两分钟后运行 `liuliang` 查看。

归属地（运营商 / 城市）是 IP 估计值，仅供参考。

## 文件分享网站（网盘）访客

同一台 VPS 上跑着文件分享网站（比如 [minishare](https://github.com/imthnio/wenjianchuanshu)）时，别人打开分享链接上传 / 下载，他的 IP 也会出现在 `liuliang` 表格里，最后一列「访问」显示「网站」。

- 节点流量还是 800KB 起显示；网站访客上传 / 下载达到 20KB 就显示（只打开一下登录页的扫描器不显示）。
- 先装了 liuliang、后装的网站（或者网站换了端口）：后台每分钟检测一次，约 2 分钟后自动开始统计，不用重装。
- 已经装过旧版的机器，重跑上面的安装命令更新一次就行，原有记录保留。
- 网站前面开了 Cloudflare 代理（橙色云）或用 Cloudflare Tunnel（cloudflared）时，也能看到真实访客 IP（v1.0.15 起，默认开启，不用改网站和 Cloudflare 设置）：
  - 公网端口上连进来的全是 Cloudflare 的地址，真实 IP 只在 HTTP 请求头 `CF-Connecting-IP` 里。liuliang 在本机回环口上看反代（Caddy / nginx / cloudflared）转给网站程序的明文请求，从请求头取访客 IP，把这次访问的流量记到他名下。只读请求头，不保存任何内容。
  - 只采信经过 Cloudflare 来的请求头，访客直连时自己伪造的头不算。
  - Cloudflare 回源节点的 IP 默认不显示（表格下方会说明隐藏了几个），`liuliang --all` 可以看到。用 WARP 连节点的用户出口也在 Cloudflare 网段，照常显示。
  - 不想要这个功能：重跑安装命令时在最后加 `--realip no`。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `liuliang` | 节点 + 网站访客表格（节点 800KB 起、网站 20KB 起显示） |
| `liuliang --web` | 只看网站访客，有网站流量就显示，不设门槛（只打开过一次页面的人也能看到） |
| `liuliang --all` | 显示全部 IP：包括没达到门槛的和 Cloudflare 回源节点 |
| `liuliang --doctor` | 自检：服务是否在跑、统计哪些端口、有没有 Cloudflare / Tunnel、最近一次认出真实访客的时间，看不到访客 IP 时先跑这个 |

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)
