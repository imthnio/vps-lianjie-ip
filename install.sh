#!/bin/sh
set -eu
if [ "$(id -u)" != 0 ]; then echo "请先使用 root 登录 VPS" >&2; exit 1; fi
# 已经装过也会继续往下走：python --install 更新程序，并保留流量记录和原端口。
# Install only standard packages from this machine's configured distribution repositories.
# apt/dpkg 锁被系统自动更新占住时等待重试（Ubuntu 刚开机常见）；非锁错误直接失败。
apt_retry() {
  _ar_rounds=$1; shift
  _ar_i=0
  while [ $_ar_i -lt "$_ar_rounds" ]; do
    if "$@" 2>/tmp/liuliang-apt.log; then return 0; fi
    grep -qiE 'Could not get lock|Unable to acquire|lock.*frontend|frontend.*lock' /tmp/liuliang-apt.log || return 1
    _ar_i=$((_ar_i + 1))
    echo "apt 正被系统更新占用，等待 20 秒后重试（$_ar_i/$_ar_rounds）…"
    sleep 20
  done
  return 1
}
apt_update() { apt-get update; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 python3 ca-certificates iproute2; DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 nftables || true; }
# 只抽出「Ubuntu 归档本身」失效的主机名。第三方源里碰巧出现 ubuntu 字样时不改。
ubuntu_eol_hosts() {
  grep -E 'no longer has a Release file' /tmp/liuliang-apt.log 2>/dev/null \
    | grep -oE 'https?://[^[:space:]'\''"]+' \
    | sed -nE 's#^https?://([^/]+)/ubuntu(/.*)?$#\1#p' \
    | sort -u
}
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache python3 ca-certificates iproute2
  apk add --no-cache nftables || true
elif command -v apt-get >/dev/null 2>&1; then
  if ! apt_retry 10 apt_update; then
    # 只有 apt 明确说某个 /ubuntu 归档没有 Release 文件时，才把那个主机换成 old-releases。
    # 别的仓库报同样的错，不能把还在维护的 archive.ubuntu.com 一起改掉。
    _hosts=$(ubuntu_eol_hosts || true)
    if [ -n "$_hosts" ]; then
      echo '检测到 Ubuntu 源已停止维护，只把失效的 Ubuntu 归档切换到 old-releases…'
      _rewrite_one() {
        _f=$1
        [ -f "$_f" ] || return 0
        printf '%s\n' "$_hosts" | while IFS= read -r host; do
          [ -n "$host" ] || continue
          host_esc=$(printf '%s' "$host" | sed 's/[].[*^$()+?{|\\]/\\&/g')
          sed -i -E "s#https?://${host_esc}/ubuntu#http://old-releases.ubuntu.com/ubuntu#g" "$_f"
        done
      }
      _rewrite_one /etc/apt/sources.list
      for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$f" ] || continue
        _rewrite_one "$f"
      done
      apt_retry 10 apt_update || { cat /tmp/liuliang-apt.log >&2; exit 1; }
    else
      cat /tmp/liuliang-apt.log >&2
      exit 1
    fi
  fi
  apt_retry 3 apt_install || { echo '依赖安装失败，apt 最后输出：' >&2; tail -5 /tmp/liuliang-apt.log >&2; exit 1; }
else
  echo "目前支持 Alpine、Debian、Ubuntu。" >&2; exit 1
fi
# ===== 自动对时 =====
# 名词小词典：对时 = 让服务器时钟和网上的标准时间保持一致；时钟不准，「最后上网」时间就会跟着错。
# Alpine 用 chronyd（OpenRC 开机自启）；systemd 系统用 systemd-timesyncd，没有就退回 chrony。
# 已经在对时就不动；容器（LXC/OpenVZ）改不了时钟，失败也不影响安装。
time_sync() {
  if command -v rc-update >/dev/null 2>&1 && [ ! -d /run/systemd/system ]; then
    if ! rc-service chronyd status >/dev/null 2>&1 && ! rc-service ntpd status >/dev/null 2>&1; then
      apk add --no-cache chrony >/dev/null 2>&1 || return 0
      rc-update add chronyd default >/dev/null 2>&1 || true
      # 容器（LXC/OpenVZ/NAT 小鸡）没权限改时钟，chronyd 起不来：撤掉自启，时间由母鸡负责。
      if ! timeout 20 rc-service chronyd start >/dev/null 2>&1; then
        rc-update del chronyd default >/dev/null 2>&1 || true
        echo '这台是容器，不能自己对时（时间跟着母鸡走），已跳过'
      fi
    fi
  elif [ -d /run/systemd/system ]; then
    for _u in chronyd chrony ntp ntpd systemd-timesyncd; do
      systemctl is-active --quiet "$_u" 2>/dev/null && return 0
    done
    if ! systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1 || ! systemctl cat systemd-timesyncd >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive timeout 120 apt-get install -y systemd-timesyncd >/dev/null 2>&1 || \
        DEBIAN_FRONTEND=noninteractive timeout 120 apt-get install -y chrony >/dev/null 2>&1 || true
    fi
    timedatectl set-ntp true >/dev/null 2>&1 || true
    systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || systemctl enable --now chrony >/dev/null 2>&1 || true
  fi
  return 0
}
echo '检查服务器时间同步…'
time_sync || true
jobdir=$(mktemp -d)
trap 'rm -rf "$jobdir"' EXIT HUP INT TERM
cat > "$jobdir/liuliang.py" <<'LIULIANG_PYTHON'
#!/usr/bin/env python3
"""Per-IP port traffic accounting. Python standard library only."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import unicodedata

VERSION = '1.0.26'
CONFIG = Path('/etc/liuliang/config.json')
DATA = Path('/var/lib/liuliang')
TABLE = 'liuliang_v1'
PROGRAM = Path('/usr/local/lib/liuliang/liuliang.py')
# 每隔多少秒把计数写进数据库一次。60 秒：最后上网时间误差不超过 1 分钟。
INTERVAL = 60
POLL = 2
LOCK = Path('/run/liuliang.lock')
# 某次 ss/conntrack 读空时，已断开的流还留这么久，避免基线丢失后把累计字节再加一遍。
FLOW_KEEP = 120
# nft set 元素超时秒数，必须与 rules() 里 `timeout 8d` 保持一致。
# 每次有包命中，内核会把该元素的 expires 重置为该值，因此可以用它
# 反推出"最后一个包"的时间（约 1 秒精度），而不用采样时刻代替。
SET_TIMEOUT = 8 * 86400
# 展示过滤阈值：近7天总流量低于该值的 IP 不在表格中显示（也不计入合计）。
# 默认 0：有流量就显示，轻度使用的人也能看到。想隐藏小流量可在
# /etc/liuliang/config.json 里加 "min_kb": 800（单位 KB）。
MIN_TRAFFIC_BYTES = 0
# 网站（文件分享网盘等非代理的对外 TCP 服务）访客的显示门槛。打开一次分享页
# 只有几 KB，扫描器打一枪也是几 KB；上传/下载一个文件就会超过这个值。
# 800KB 门槛只管节点流量，网站访客按这里单独判断。
WEB_MIN_BYTES = 20 * 1024
# 后台每隔这么久重新看一次本机监听端口：装好 liuliang 之后才装的网站/节点
# （或者换了端口）会自动并入统计，不用再重跑安装。连续两次都看到才并入，
# 避免临时起来又关掉的端口混进来。
RESCAN = 60


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def ports(value):
    pieces = re.split(r'[,\s]+', value.strip())
    if not pieces or any(not re.fullmatch(r'[0-9]{1,5}', p) for p in pieces):
        raise ValueError('端口格式应为 443 或 443,8443')
    result = sorted(set(map(int, pieces)))
    if any(p < 1 or p > 65535 for p in result) or len(result) > 64:
        raise ValueError('端口须在 1–65535，最多64个')
    return result


def rules(selected, web=()):
    """up/down 四个集合按 IP 数全部端口的字节；web4/web6 只数网站端口（两个方向合计）。"""
    selected = ports(','.join(map(str, selected)))
    portset = '{ ' + ', '.join(map(str, selected)) + ' }'
    web = sorted(set(web) & set(selected))
    webset = '{ ' + ', '.join(map(str, web)) + ' }'
    lines = ['table inet ' + TABLE + ' {']
    names = [(d, v) for d in ('up', 'down') for v in (4, 6)]
    if web:
        names += [('web', 4), ('web', 6)]
    for direction, version in names:
        lines.append(f' set {direction}{version} {{ type ipv{version}_addr; flags dynamic,timeout; timeout 8d; size 16384; }}')
    for chain, direction, field, address in [('input','up','dport','saddr'), ('output','down','sport','daddr')]:
        lines.append(f' chain {chain} {{ type filter hook {chain} priority 11; policy accept;')
        for version, family in [(4, 'ip'), (6, 'ip6')]:
            for protocol in ('tcp', 'udp'):
                lines.append(f'  meta nfproto ipv{version} {protocol} {field} {portset} update @{direction}{version} {{ {family} {address} counter }}')
            if web:
                lines.append(f'  meta nfproto ipv{version} tcp {field} {webset} update @web{version} {{ {family} {address} counter }}')
        lines.append(' }')
    return '\n'.join(lines + ['}', ''])


def ensure_table():
    probe = subprocess.run(['nft','list','table','inet',TABLE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode == 0:
        return False
    run(['nft','-f','/etc/liuliang/counters.nft'], capture_output=True)
    return True


def parse_duration(value):
    """把 expires 超时转成秒。

    不同 nft 版本的 -j 输出里，expires 可能是数字（秒），也可能是
    '7d23h59m' 或 '26s484ms' 这样的字符串。毫秒单位必须写在前面，
    否则 '484ms' 会被拆成 484 分钟。拿不到有效值时返回 None，
    调用方回退到采样时刻（精度降级，但不崩）。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or '').strip()
    if re.fullmatch(r'[0-9]+', text):
        return int(text)
    total = 0
    seen = False
    for amount, unit in re.findall(r'([0-9]+)\s*(ms|[dhms])', text):
        seen = True
        total += int(amount) * {'d': 86400, 'h': 3600, 'm': 60, 's': 1, 'ms': 0.001}[unit]
    if not seen:
        return None
    return int(total) or None


# 名词小词典：私有地址 = 10.x、172.16-31.x、192.168.x；CGNAT = 100.64-127.x（运营商级 NAT）。
# NAT 小鸡上，商家网关会把所有来访地址换成它自己的私有地址（如 10.91.0.1），
# 这时看不到真实 IP，但流量还是要算，所以这两类地址也入库。
NAT_NETS = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')]


def is_nat_ip(value):
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return ip.version == 4 and any(ip in n for n in NAT_NETS)


def acceptable_ip(value):
    """可入库的地址：公网地址，以及私有/CGNAT 地址（NAT 小鸡的网关）。回环、组播、链路本地、保留丢掉。

    Python 3.9 的 IPv4Address.is_global 不排除组播，所以这里逐项判断。
    """
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if is_nat_ip(ip):
        return ip
    if ip.is_multicast or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
        return None
    if getattr(ip, 'is_global', True) is False:
        return None
    return ip


def parse_counters(document):
    """返回 {(set 名, ip): (累计字节数, expires)}。

    expires 是该元素距离超时还剩的秒数（nft -j 输出）；元素每次被包命中
    都会被重置为 SET_TIMEOUT。若 nft 没给 expires（如旧版本），则为 None。
    """
    result = {}
    def walk(obj, setname):
        if isinstance(obj, dict):
            counter = obj.get('counter')
            value = obj.get('val', obj.get('elem'))
            if isinstance(counter, dict) and 'bytes' in counter:
                ip = acceptable_ip(value)
                if ip is not None:
                    try:
                        result[(setname, str(ip))] = (
                            int(counter['bytes']),
                            parse_duration(obj.get('expires')),
                        )
                    except (TypeError, ValueError):
                        pass
            for child in obj.values():
                walk(child, setname)
        elif isinstance(obj, list):
            for child in obj:
                walk(child, setname)
    for entry in document.get('nftables', []):
        obj = entry.get('set', {})
        if obj.get('name') in ('up4','down4','up6','down6','web4','web6'):
            walk(obj.get('elem', []), obj['name'])
    return result


def open_db(path=None):
    c = sqlite3.connect(str(path or DATA / 'history-v1.db'), timeout=30)
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript('''
        CREATE TABLE IF NOT EXISTS clients(ip TEXT PRIMARY KEY, country TEXT DEFAULT '', city TEXT DEFAULT '', isp TEXT DEFAULT '', last_seen REAL NOT NULL, geo_due REAL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS traffic(ts REAL NOT NULL, ip TEXT NOT NULL, bytes INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS traffic_ip_ts ON traffic(ip,ts);
        CREATE INDEX IF NOT EXISTS traffic_ts ON traffic(ts);
        CREATE TABLE IF NOT EXISTS counters(name TEXT, ip TEXT, bytes INTEGER NOT NULL, PRIMARY KEY(name,ip));
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS flows(key TEXT PRIMARY KEY, up INTEGER NOT NULL, down INTEGER NOT NULL, seen REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS pending(ip TEXT PRIMARY KEY, bytes INTEGER NOT NULL, last_seen REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sites(ts REAL NOT NULL, ip TEXT NOT NULL, host TEXT NOT NULL, bytes INTEGER NOT NULL, hits INTEGER NOT NULL, last REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS sites_ip_ts ON sites(ip,ts);
        CREATE INDEX IF NOT EXISTS sites_ts ON sites(ts);
    ''')
    # web：这一笔字节里走网站端口的部分（不另算，web <= bytes）。老库自动加列。
    for table in ('traffic', 'pending'):
        if 'web' not in [row[1] for row in c.execute(f'PRAGMA table_info({table})')]:
            c.execute(f'ALTER TABLE {table} ADD COLUMN web INTEGER NOT NULL DEFAULT 0')
            c.commit()
    cols = [row[1] for row in c.execute('PRAGMA table_info(clients)')]
    if 'isp' not in cols:
        c.execute("ALTER TABLE clients ADD COLUMN isp TEXT DEFAULT ''")
        # Re-resolve existing rows once so they gain an ISP label.
        c.execute("UPDATE clients SET geo_due=0 WHERE country<>''")
        c.commit()
    return c


def save_sample(c, current, now, reset=False):
    if reset:
        c.execute('DELETE FROM counters')
    previous = {(name, ip): n for name, ip, n in c.execute('SELECT name,ip,bytes FROM counters')}
    activity = {}
    web = {}
    last_seen = {}
    for (name, ip), (n, expires) in current.items():
        old = previous.get((name, ip), 0)
        delta = n - old if n >= old else n
        if delta > 0 and name.startswith('web'):
            # 网站端口的字节已经算在 up/down 里，这里只记其中多少是网站的。
            web[ip] = web.get(ip, 0) + delta
        elif delta > 0:
            activity[ip] = activity.get(ip, 0) + delta
            if expires is not None:
                # 该 set 元素在本轮采样内被包命中过：用 expires 反推最后
                # 一个包的时间（约 1 秒精度），比直接用采样时刻准得多。
                t = min(max(now - (SET_TIMEOUT - expires), 0), now)
                if t > last_seen.get(ip, 0):
                    last_seen[ip] = t
        c.execute('INSERT OR REPLACE INTO counters VALUES(?,?,?)', (name, ip, n))
    for name, ip in previous.keys() - current.keys():
        c.execute('DELETE FROM counters WHERE name=? AND ip=?', (name, ip))
    for ip, n in activity.items():
        c.execute('INSERT INTO traffic(ts,ip,bytes,web) VALUES(?,?,?,?)', (now, ip, n, min(web.get(ip, 0), n)))
        # 取四个方向里最晚的那个包的时间；没有 expires 时回退到采样时刻；
        # max() 保证 last_seen 只增不减，避免时钟抖动造成时间倒退。
        c.execute('INSERT INTO clients(ip,last_seen) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET last_seen=max(clients.last_seen, excluded.last_seen)', (ip, last_seen.get(ip, now)))
    c.execute('DELETE FROM traffic WHERE ts<?', (now - 8*86400,))
    c.execute('DELETE FROM clients WHERE last_seen<?', (now - 8*86400,))
    c.commit()


def geo_lookup(ip):
    # 用到时才加载网络模块，后台常驻时少占几 MB 内存。
    import urllib.parse, urllib.request
    url = 'https://ipwho.is/' + urllib.parse.quote(ip, safe=':') + '?fields=success,country_code,city,connection.isp&lang=zh-CN'
    req = urllib.request.Request(url, headers={'User-Agent':'liuliang/' + VERSION})
    with urllib.request.urlopen(req, timeout=3) as response:
        data = json.load(response)
    if not data.get('success'):
        raise ValueError('归属地查询暂不可用')
    # Never render terminal control sequences supplied by an external service.
    clean = lambda s: ''.join(ch for ch in str(s or '') if ch.isprintable())[:60]
    connection = data.get('connection') or {}
    return clean(data.get('country_code')), clean(data.get('city')), clean(connection.get('isp'))


def isp_display(raw):
    """Short carrier label: Chinese carriers in Chinese, others as returned."""
    s = ''.join(ch for ch in str(raw or '') if ch.isprintable()).strip()
    low = s.lower()
    if 'china mobile' in low:
        return '中国移动'
    if 'china telecom' in low:
        return '中国电信'
    if 'china unicom' in low or 'china united network' in low:
        return '中国联通'
    if not s:
        return '未解析'
    return s[:18]


# 表格里运营商一栏最多显示这么宽（中文算 2），太长的截断加 …，让表格窄一点。
# 名词小词典：扫描 = 服务商或网上的机器人挨个探测端口，每个 IP 只来几 KB、从不真正上网；
# /16 = IP 的前两段相同（如 175.30.x.x），同一家机房/运营商的一批地址。
# 判定规则（门槛都可在 /etc/liuliang/config.json 里改，填 0 关闭该条）：
#   1. scan_tiny_kb（默认 16）：近7天总共不到这么多 KB；
#   2. scan_kb（默认 64）：不到这么多 KB，且只有一个方向有数据（另一方向 0 B）；
#   3. scan_batch（默认 5）个以上同一 /16 的新 IP，在 scan_window（默认 60）秒内先后出现，
#      每个都不到 scan_batch_kb（默认 50）KB：整批算扫描。
# 三条都只针对「访问日志里没打开过网站、也不是网站访客」的 IP，真人用户不会被藏。
def scan_ips(c, rows, config, opened, now, hasweb=True):
    kb = lambda key, d: int(config.get(key, d) or 0) * 1024
    tiny, small, batch_kb = kb('scan_tiny_kb', 16), kb('scan_kb', 64), kb('scan_batch_kb', 50)
    batch, window = int(config.get('scan_batch', 5) or 0), float(config.get('scan_window', 60) or 0)
    since = now - 604800
    # 每个 IP 两个方向的字节（nft 计数里 up=用户发来，down=发给用户）。
    dirs = {}
    for name, ip, n in c.execute('SELECT name,ip,bytes FROM counters'):
        d = dirs.setdefault(ip, [0, 0]); d[0 if name.startswith('up') else 1] += n if name[:2] in ('up', 'do') else 0
    cand, bad = [], set()
    for r in rows:
        ip, w = r[0], r[4]
        if opened.get(ip) or (hasweb and diff(c, ip, since, now, 'web') > 0):
            continue
        d = dirs.get(ip)
        if (tiny and w < tiny) or (small and w < small and d and min(d) == 0 and max(d) > 0):
            bad.add(ip); continue
        cand.append(r)
    if batch and window:
        groups = {}
        for r in cand:
            if r[4] >= batch_kb or ':' in r[0]:
                continue
            first = c.execute('SELECT min(ts) FROM traffic WHERE ip=?', (r[0],)).fetchone()[0] or now
            groups.setdefault('.'.join(r[0].split('.')[:2]), []).append((first, r[0]))
        for items in groups.values():
            items.sort()
            j = 0
            for i in range(len(items)):
                while items[i][0] - items[j][0] > window:
                    j += 1
                if i - j + 1 >= batch:
                    bad.update(ip for _t, ip in items[j:i + 1])
    return bad


def short(text, width=10):
    # 截断用两个点 '..'（各占 1 格），不用 '…'：它在有的终端占 1 格、有的占 2 格，会让表格对不齐。
    text = str(text); out = ''
    for ch in text:
        if ww(out + ch) > width - (2 if ww(text) > width else 0):
            return out + '..'
        out += ch
    return out


def collect(config, sniffer=None, sites=None):
    if config.get('backend') == 'diag':
        diag_tick(config, True, sniffer=sniffer, sites=sites)
        if config.get('geo', True):
            geo_resolve()
        return
    with open(LOCK, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        recreated = ensure_table()
        doc = json.loads(run(['nft','-j','list','table','inet',TABLE], capture_output=True).stdout)
        current = parse_counters(doc)
        now = time.time()
        c = open_db()
        try:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            last_boot = c.execute("SELECT value FROM metadata WHERE key='boot'").fetchone()
            save_sample(c, current, now, recreated or not last_boot or last_boot[0] != boot)
            save_realip(c, sniffer, now)
            take_pending(c, now)
            save_sites(c, sites, now)
            save_nic(c, now)
            c.execute("INSERT OR REPLACE INTO metadata VALUES('boot',?)", (boot,))
            c.execute("INSERT OR REPLACE INTO metadata VALUES('sample',?)", (str(now),))
            c.commit()
        finally:
            c.close()
    # Geo lookups run outside the lock: each one is a network round trip
    # (up to 10 per cycle), and holding the lock that long would stall any
    # concurrent `liuliang --once`. The DB itself is safe via WAL + busy timeout.
    if config['geo']:
        geo_resolve()


def geo_resolve():
    now = time.time()
    c = open_db()
    try:
        for ip, in c.execute('SELECT ip FROM clients WHERE geo_due<=? ORDER BY last_seen DESC LIMIT 10', (now,)).fetchall():
            if is_nat_ip(ip):   # 内网地址查不到归属地，不浪费网络
                c.execute("UPDATE clients SET country='',city='内网',geo_due=? WHERE ip=?", (now + 30 * 86400, ip)); c.commit(); continue
            try:
                country, city, isp = geo_lookup(ip)
                c.execute('UPDATE clients SET country=?,city=?,isp=?,geo_due=? WHERE ip=?', (country,city,isp,now+30*86400,ip))
            except Exception:
                c.execute('UPDATE clients SET geo_due=? WHERE ip=?', (now+86400,ip))
            c.commit()
    finally:
        c.close()


PROXY_PROCESS = re.compile(
    r'(xray|v2ray|sing-box|hysteria|tuic|juicity|shadowsocks|ss-server|ssserver|trojan|anytls|shadowtls|naive|gost|brook)',
    re.I,
)

def ephemeral_bounds():
    """本机临时端口区间。UDP 客户端套接字也落在这里，不能当成监听端口。"""
    try:
        low, high = Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()[:2]
        return int(low), int(high)
    except (OSError, ValueError):
        return 32768, 60999


def in_ephemeral(port, bounds=None):
    low, high = bounds or ephemeral_bounds()
    return low <= port <= high


def split_host_port(token):
    match = re.search(r':([0-9]+)$', token)
    if not match:
        return None, None
    host = token[:match.start()]
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    return host.split('%', 1)[0], int(match.group(1))


def bind_scope(host):
    """any=通配监听，loop=只有本机能连，public=绑在具体地址上。"""
    if host in ('*', '0.0.0.0', '::', ''):
        return 'any'
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return 'public'
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        ip = mapped
    if ip.is_loopback or ip.is_link_local:
        return 'loop'
    return 'public'


def process_name(line):
    found = re.search(r'\(\("([^"]+)"', line)
    if found:
        return found.group(1)
    found = re.search(r'(?:^|\s)\d+/(\S+)', line)
    return found.group(1) if found else ''


def read_socket_table():
    # TCP 和 UDP 都要列出来：hy2 这类纯 UDP 代理只监听 UDP，
    # 以前只跑 -lntup（t = 仅 TCP），它的端口根本看不见。
    if shutil.which('ss'):
        commands = [['ss', '-H', '-lntup'], ['ss', '-H', '-lnup'],
                    ['ss', '-lntup'], ['ss', '-lnup']]
    else:
        commands = [['netstat', '-lntup'], ['netstat', '-lnup']]
    chunks = []
    for cmd in commands:
        try:
            chunks.append(run(cmd, capture_output=True).stdout)
        except (OSError, subprocess.CalledProcessError):
            continue
    return '\n'.join(chunks)


def iter_sockets(text):
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        words = stripped.split()
        head = words[0].lower()
        if head in ('netid', 'proto', 'state', 'active'):
            continue
        endpoints = []
        for word in words:
            host, port = split_host_port(word)
            if host is None or not 1 <= port <= 65535:
                continue
            endpoints.append((host, port))
        if not endpoints:
            continue
        host, port = endpoints[0]
        if head.startswith('udp'):
            proto = 'udp'
        elif head.startswith('tcp') or 'listen' in stripped.lower():
            proto = 'tcp'
        else:
            continue
        yield {'proto': proto, 'port': port, 'host': host, 'scope': bind_scope(host), 'line': stripped, 'name': process_name(stripped)}


def server_ports(group, bounds):
    """一个进程真正在对外服务的端口。

    ss -lu 会把 UDP 客户端的临时端口也列出来。代理若已有 TCP 监听，
    只保留同端口的 UDP；纯 UDP 进程则丢掉临时端口，除非它只监听临时端口
    （NAT VPS 经常把内部端口分在这个区间里）。
    """
    tcp = {item['port'] for item in group if item['proto'] == 'tcp'}
    udp = [item for item in group if item['proto'] == 'udp']
    udp_open = [item for item in udp if item['scope'] != 'loop']
    if tcp:
        ports = set(tcp)
        ports.update(item['port'] for item in udp_open if item['port'] in tcp)
        return ports
    chosen = udp_open or udp
    outside = {item['port'] for item in chosen if not in_ephemeral(item['port'], bounds)}
    if outside:
        return outside
    return {item['port'] for item in chosen}


def detect_ports(proxy_only=True):
    """返回 (端口列表, 来源)。来源是 proxy / frontend / loopback / service / fallback / none。"""
    return scan_ports(proxy_only)[:2]


def scan_ports(proxy_only=True):
    """返回 (端口列表, 来源, 网站端口)。网站端口 = 非代理进程的对外 TCP 端口。

    除了代理端口（TCP+UDP），还会带上其他对外服务的 TCP 端口
    （比如文件传输网站），SSH 22 除外，这样哪台机器上的网站被谁访问了也能看到。
    """
    bounds = ephemeral_bounds()
    sockets = list(iter_sockets(read_socket_table()))
    grouped = {}
    for item in sockets:
        if not PROXY_PROCESS.search(item['line']):
            continue
        grouped.setdefault(item['name'] or item['line'], []).append(item)
    public, loopback = set(), set()
    for group in grouped.values():
        for port in server_ports(group, bounds):
            scopes = {item['scope'] for item in group if item['port'] == port}
            if 'any' in scopes or 'public' in scopes:
                public.add(port)
            else:
                loopback.add(port)
    # 非代理进程的对外 TCP 端口：文件传输网站、面板等。UDP 不收，
    # 不然 dhclient 这类客户端的 UDP 端口会混进来。
    service = {
        item['port'] for item in sockets
        if item['proto'] == 'tcp' and item['port'] != 22 and item['scope'] != 'loop'
        and not item['name'].startswith('sshd') and not PROXY_PROCESS.search(item['line'])
    }
    web = sorted(service)
    if proxy_only:
        if public:
            return sorted(public | service), 'proxy', web
        if loopback:
            if service:
                return sorted(service), 'frontend', web
            return sorted(loopback), 'loopback', web
        if service:
            return sorted(service), 'service', web
        return [], 'none', web
    fallback = set()
    for item in sockets:
        if item['port'] == 22 or item['scope'] == 'loop':
            continue
        if item['proto'] == 'tcp' or not in_ephemeral(item['port'], bounds):
            fallback.add(item['port'])
    return sorted(fallback), ('fallback' if fallback else 'none'), web


def listening_ports(proxy_only=True):
    """Return sorted ports to account.

    proxy_only=True: proxy listen ports (TCP and UDP, so a pure-UDP proxy like
    hysteria2 is included) plus other public TCP service ports (e.g. a
    file-transfer website), except SSH 22. Loopback-only proxies fall through
    to the public TCP ports in front of them (nginx/caddy), because client
    addresses never appear on 127.0.0.1. UDP client sockets are not included.
    proxy_only=False: public TCP listeners except SSH 22, plus UDP listeners
    outside the ephemeral range.
    """
    return detect_ports(proxy_only)[0]


def saved_config():
    """已安装时读出端口和城市查询开关。读不到就当没装过。"""
    try:
        data = json.loads(CONFIG.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get('ports'):
        return None
    return data


def resolve_install(existing, args, detected=None):
    """决定这次安装用哪些端口、是否查城市、是不是在更新。

    更新时保留原来的端口和城市查询开关：新检测到的端口会自动并进来
    （老版本可能漏检，比如纯 UDP 代理的端口），但已有端口一个不删，
    避免代理重启瞬间检测不到导致端口丢失。只有命令行明确写了 --ports
    / --geo 才覆盖。流量数据库不在这里处理，调用方不能删它。
    """
    updating = existing is not None
    if args.ports:
        selected = ports(args.ports)
    elif updating:
        saved = ports(','.join(str(port) for port in existing['ports']))
        new_ports = sorted(set(saved) | set(detected or []))[:64]
        selected = ports(','.join(str(port) for port in new_ports))
    elif detected:
        selected = ports(','.join(str(port) for port in detected))
    else:
        raise RuntimeError('未检测到任何监听端口：请先把节点装好，再重跑一键安装')
    if args.geo is not None:
        geo = args.geo != 'no'
    elif updating:
        geo = bool(existing.get('geo', True))
    else:
        geo = True
    return selected, geo, updating


def table_loaded():
    probe = subprocess.run(['nft', 'list', 'table', 'inet', TABLE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return probe.returncode == 0


def stop_service(init):
    cmd = ['systemctl', 'stop', 'liuliang'] if init == 'systemd' else ['rc-service', 'liuliang', 'stop']
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def normalize_ip(value):
    """ss / conntrack 里的地址转成可入库的 IP。IPv4 映射地址先拆成 IPv4。"""
    text = str(value or '').strip().strip('[]')
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text.split('%', 1)[0])
    except ValueError:
        return None
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        ip = mapped
    return acceptable_ip(ip)


def nft_works(nft_text):
    """nft -c 会连内核。容器没给 NET_ADMIN 时这里就是 Operation not permitted。"""
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.nft') as handle:
            handle.write(nft_text)
            handle.flush()
            run(['nft', '-c', '-f', handle.name], capture_output=True)
        return True, ''
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, 'stderr', None) or ''
        lines = stderr.strip().splitlines()
        return False, (lines[-1] if lines else '')


def read_ss():
    """先试 -H。老版 iproute2 不认识 -H 时退回带表头的输出，解析时会跳过表头。"""
    for cmd in (['ss', '-H', '-tin'], ['ss', '-tin']):
        try:
            return run(cmd, capture_output=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
    return None


def ss_works():
    if not shutil.which('ss'):
        return False
    return read_ss() is not None


def conntrack_text():
    for path in ('/proc/net/nf_conntrack', '/proc/net/ip_conntrack'):
        try:
            with open(path, 'r', errors='replace') as handle:
                return handle.read()
        except OSError:
            continue
    return None


def capture_devices():
    """抓包只用默认路由那块网卡，避免同一包在两块网卡上各数一次。"""
    try:
        names = [name for _idx, name in socket.if_nameindex() if name != 'lo']
    except OSError:
        return []
    try:
        lines = Path('/proc/net/route').read_text().splitlines()[1:]
    except OSError:
        lines = []
    for line in lines:
        cols = line.split()
        if len(cols) >= 2 and cols[1] == '00000000' and cols[0] in names:
            return [cols[0]]
    return names[:1]


# ===== 整块网卡用量（和服务商后台对账用）=====
# 名词小词典：网卡 = 服务器连外网的那块网络接口（默认路由走的那块）；
# rx = 收到的字节（进站），tx = 发出的字节（出站）；/proc/net/dev 里是开机以来的累计值，重启会归零。
BILLING = {'both': '进+出', 'out': '出站', 'max': '取大'}


def nic_bytes(dev, text=None):
    """读 /proc/net/dev，返回这块网卡的 (收, 发) 累计字节；读不到返回 None。"""
    try:
        text = Path('/proc/net/dev').read_text() if text is None else text
    except OSError:
        return None
    for line in text.splitlines():
        if ':' not in line:
            continue
        name, rest = line.split(':', 1)
        if name.strip() == dev:
            cols = rest.split()
            try:
                return int(cols[0]), int(cols[8])
            except (IndexError, ValueError):
                return None
    return None


def save_nic(c, now, dev=None, counts=None):
    """把这次和上次之间网卡多收/多发的字节存进 nic 表；计数变小（重启/换网卡）就从 0 算起。"""
    c.execute('CREATE TABLE IF NOT EXISTS nic(ts REAL NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL)')
    if dev is None:
        devs = capture_devices()
        dev = devs[0] if devs else None
    if not dev:
        return
    counts = nic_bytes(dev) if counts is None else counts
    if counts is None:
        return
    rx, tx = counts
    row = c.execute("SELECT value FROM metadata WHERE key='nic'").fetchone()
    try:
        old = json.loads(row[0]) if row else None
    except ValueError:
        old = None
    if old and old.get('dev') == dev:
        drx = rx - old['rx'] if rx >= old['rx'] else rx
        dtx = tx - old['tx'] if tx >= old['tx'] else tx
        if drx > 0 or dtx > 0:
            c.execute('INSERT INTO nic(ts,rx,tx) VALUES(?,?,?)', (now, drx, dtx))
    c.execute("INSERT OR REPLACE INTO metadata VALUES('nic',?)", (json.dumps({'dev': dev, 'rx': rx, 'tx': tx}),))
    # 网卡数据很小，留 40 天，够覆盖一整个月的计费周期。
    c.execute('DELETE FROM nic WHERE ts<?', (now - 40 * 86400,))


def nic_usage(c, since, until):
    """这段时间网卡的 (收, 发) 合计。"""
    try:
        return tuple(c.execute('SELECT coalesce(sum(rx),0),coalesce(sum(tx),0) FROM nic WHERE ts>? AND ts<=?', (since, until)).fetchone())
    except sqlite3.OperationalError:
        return (0, 0)


# 名词小词典：计费周期 = 服务商每月重置流量的那一天到下个月同一天；
# 重置日是 31 号而这个月只有 30 天时，就按这个月最后一天算（月底对齐）。
def cycle_bounds(ts, day):
    """返回 ts 所在计费周期的 (开始, 结束) 时间戳，按北京时间（和表格一致）。"""
    import calendar
    day = min(max(int(day or 1), 1), 31)
    def start_of(y, m):
        return datetime(y, m, min(day, calendar.monthrange(y, m)[1]), tzinfo=Z)
    now = datetime.fromtimestamp(ts, Z)
    y, m = now.year, now.month
    start = start_of(y, m)
    if now < start:
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
        start = start_of(y, m)
    ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
    return start.timestamp(), start_of(ny, nm).timestamp()


def billing_figure(mode, rx, tx):
    return {'both': rx + tx, 'out': tx, 'max': max(rx, tx)}[mode]


def billing_lines(config, c, now):
    """合计下面那几行：服务商口径的整块网卡用量。"""
    d = nic_usage(c, now - 86400, now); w = nic_usage(c, now - 604800, now)
    # 本计费周期：从上一个重置日到现在。
    a, b = cycle_bounds(now, config.get('reset_day', 1)); cyc = nic_usage(c, a, now)
    if not any(d + w + cyc):
        return []
    # 每行不超过 50 格，手机竖屏不折行。
    span = '%s~%s' % (datetime.fromtimestamp(a, Z).strftime('%m-%d'), datetime.fromtimestamp(b - 1, Z).strftime('%m-%d'))
    mode = config.get('billing', 'both')
    if mode in BILLING:
        out = ['服务商口径（%s）本周期 %s' % (BILLING[mode], span),
               '  共 %s · 24小时 %s · 7天 %s' % (sz(billing_figure(mode, *cyc)), sz(billing_figure(mode, *d)), sz(billing_figure(mode, *w)))]
    else:
        out = ['整块网卡用量 本周期 %s' % span,
               '  ' + ' · '.join('%s %s' % (BILLING[k], sz(billing_figure(k, *cyc))) for k in ('out', 'both', 'max')),
               '  和服务商后台对一下，对上的就是计费方式',
               '  改计费方式：liuliang --billing']
    out.append('网卡用量含 SSH、系统更新等全部流量')
    return out


def set_billing(value=None):
    """liuliang --billing：改服务商计费方式。不带值时一步一步问。"""
    config = json.loads(CONFIG.read_text())
    if value is None:
        value = ask_billing(config.get('billing', 'both'))
    config['billing'] = value
    CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
    print('已设置计费方式：' + BILLING.get(value, '不确定（三种都显示）'))


def parse_reset_day(text):
    """每月重置日：1-31 的整数，其他返回 None。"""
    text = str(text).strip()
    return int(text) if re.fullmatch(r'[0-9]{1,2}', text) and 1 <= int(text) <= 31 else None


def ask_reset_day(current=1):
    """问一次每月几号重置流量，直接回车 = 当前值（默认 1 号）。输错了再问。"""
    while True:
        got = ask('服务商每月几号重置流量？输入 1-31（直接回车 = %d 号；31 号遇到小月按月底算）：' % current)
        if not got:
            return current
        day = parse_reset_day(got)
        if day:
            return day
        print('请输入 1 到 31 之间的数字')


def set_reset_day(value=None):
    """liuliang --reset-day N：改每月重置日；不带数字时一步一步问。"""
    config = json.loads(CONFIG.read_text())
    if value is None:
        day = ask_reset_day(int(config.get('reset_day') or 1))
    else:
        day = parse_reset_day(value)
        if not day:
            raise ValueError('重置日要是 1 到 31 之间的数字')
    config['reset_day'] = day
    CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
    print('已设置：每月 %d 号重置流量' % day)


def ask_billing(current='both'):
    """问一次服务商怎么算流量。直接回车 = 当前/推荐的选项。"""
    keys = ['both', 'out', 'max', 'all']
    names = ['进+出双向（大多数服务商）', '只算出站', '进和出取大的那个', '不确定，三种都显示']
    print('你的服务商怎么算流量？（看服务商后台或套餐说明）')
    for i, n in enumerate(names, 1):
        print('  %d) %s%s' % (i, n, '  ← 直接回车' if keys[i-1] == current else ''))
    got = ask('输入序号：')
    return keys[int(got) - 1] if got in ('1', '2', '3', '4') else current


def raw_possible():
    if not hasattr(socket, 'AF_PACKET'):
        return False
    names = capture_devices()
    if not names:
        return False
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.ntohs(0x0003))
    except OSError:
        return False
    try:
        sock.bind((names[0], 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def detect_diag_sources():
    """nft 不可用时还能怎么数字节。TCP 优先 ss（不要 NET_ADMIN），UDP 再看 conntrack / 抓包。"""
    tcp = 'ss' if ss_works() else None
    udp = None
    if conntrack_text() is not None:
        udp = 'conntrack'
        if tcp is None:
            tcp = 'conntrack'
    if (tcp is None or udp is None) and raw_possible():
        if tcp is None:
            tcp = 'raw'
        if udp is None:
            udp = 'raw'
    return {'tcp': tcp, 'udp': udp}


def probe_backend(nft_text):
    ok, detail = nft_works(nft_text)
    if ok:
        return 'nft', {}, ''
    sources = detect_diag_sources()
    if sources.get('tcp') or sources.get('udp'):
        return 'diag', sources, detail
    raise RuntimeError(
        '这台机器用不了 nftables'
        + ('（' + detail + '）' if detail else '')
        + '，连接采样也起不来（ss、conntrack、抓包都不可用）。'
          'liuliang 需要其中一种来按 IP 统计流量。'
    )


def explain_diag(detail, sources):
    why = ('（' + detail + '）') if detail else ''
    tcp_how = {
        'ss': 'TCP 读取每个连接的收发字节',
        'conntrack': 'TCP 读取 conntrack',
        'raw': 'TCP 按网卡计数',
    }.get(sources.get('tcp'), 'TCP 统计不到')
    udp_how = {
        'conntrack': 'UDP 读取 conntrack',
        'raw': 'UDP 按网卡计数',
    }.get(sources.get('udp'), 'UDP 统计不到（纯 UDP 代理如 hy2 这次没有字节数）')
    print('nftables 不可用' + why + '。改用连接采样，安装继续：' + tcp_how + '；' + udp_how + '。')


def parse_ss(text, selected):
    """ss -tin：本机端口上的 TCP 连接。bytes_received 是客户端上行，bytes_sent 是下行。"""
    flows = {}
    selected = set(selected)
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.strip() or line[:1].isspace():
            i += 1
            continue
        endpoints = []
        for word in line.split():
            host, port = split_host_port(word)
            if host is None or not 1 <= port <= 65535:
                continue
            endpoints.append((host, port))
        info = []
        i += 1
        while i < n and lines[i][:1].isspace():
            info.append(lines[i])
            i += 1
        if len(endpoints) < 2:
            continue
        local_host, local_port = endpoints[0]
        peer_host, peer_port = endpoints[1]
        if local_port not in selected:
            continue
        blob = line + ' ' + ' '.join(info)
        sent = re.search(r'\bbytes_sent:(\d+)', blob) or re.search(r'\bbytes_acked:(\d+)', blob)
        recv = re.search(r'\bbytes_received:(\d+)', blob)
        if not sent and not recv:
            continue
        ip = normalize_ip(peer_host)
        if ip is None:
            continue
        up = int(recv.group(1)) if recv else 0
        down = int(sent.group(1)) if sent else 0
        key = 'tcp|%s|%s|%s|%s' % (local_host, local_port, peer_host, peer_port)
        flows[key] = (str(ip), up, down)
    return flows


CT_FLOW = re.compile(
    r'\bsrc=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)(?:\s+\S+=\S+)*?\s+bytes=(\d+)'
)


def parse_conntrack(text, selected, tcp=False, udp=False):
    flows = {}
    if not text or (not tcp and not udp):
        return flows
    selected = set(selected)
    for line in text.splitlines():
        head = line.split()
        if len(head) < 3 or head[2] not in ('tcp', 'udp'):
            continue
        proto = head[2]
        if (proto == 'tcp' and not tcp) or (proto == 'udp' and not udp):
            continue
        found = CT_FLOW.search(line)
        if not found:
            continue
        src, dst, sport, dport, nbytes = found.groups()
        sport, dport, up = int(sport), int(dport), int(nbytes)
        if dport not in selected:
            continue
        ip = normalize_ip(src)
        if ip is None:
            continue
        down = 0
        reply = CT_FLOW.search(line[found.end():])
        if reply:
            down = int(reply.group(5))
        prefix = 'ctcp' if proto == 'tcp' else 'udp'
        key = '%s|%s|%s|%s|%s' % (prefix, src, sport, dst, dport)
        flows[key] = (str(ip), up, down)
    return flows


def parse_ip_packet(pkt):
    if len(pkt) < 20:
        return None
    version = pkt[0] >> 4
    if version == 4:
        ihl = (pkt[0] & 0x0f) * 4
        if ihl < 20 or len(pkt) < ihl + 4:
            return None
        if int.from_bytes(pkt[6:8], 'big') & 0x1fff:
            return None
        total = int.from_bytes(pkt[2:4], 'big') or len(pkt)
        return pkt[9], str(ipaddress.IPv4Address(pkt[12:16])), str(ipaddress.IPv4Address(pkt[16:20])), pkt[ihl:], total
    if version != 6 or len(pkt) < 40:
        return None
    total = 40 + int.from_bytes(pkt[4:6], 'big')
    nxt = pkt[6]
    src = str(ipaddress.IPv6Address(pkt[8:24]))
    dst = str(ipaddress.IPv6Address(pkt[24:40]))
    off = 40
    seen = 0
    while nxt in (0, 43, 60) and seen < 8 and off + 2 <= len(pkt):
        nxt_next = pkt[off]
        ext_len = (pkt[off + 1] + 1) * 8
        if ext_len < 8 or off + ext_len > len(pkt):
            return None
        off += ext_len
        nxt = nxt_next
        seen += 1
    if nxt in (44, 51) or off > len(pkt):
        return None
    return nxt, src, dst, pkt[off:], total


def account_packet(pkt, ports, count_tcp, count_udp):
    parsed = parse_ip_packet(pkt)
    if not parsed:
        return None, 0
    proto, src, dst, l4, total = parsed
    if proto == 6 and not count_tcp:
        return None, 0
    if proto == 17 and not count_udp:
        return None, 0
    if proto not in (6, 17) or len(l4) < 4:
        return None, 0
    sport, dport = struct.unpack('!HH', l4[:4])
    if dport in ports:
        ip = normalize_ip(src)
    elif sport in ports:
        ip = normalize_ip(dst)
    else:
        return None, 0
    if ip is None or total <= 0:
        return None, 0
    return str(ip), total


class PacketPump:
    """没权限改防火墙时，用 AF_PACKET 数选中端口的 IP 包长。只累计字节，不保存内容。"""

    def __init__(self, ports, count_tcp, count_udp, web=()):
        self.ports = set(ports)
        self.web = set(web)
        self.count_tcp = count_tcp
        self.count_udp = count_udp
        self.lock = threading.Lock()
        self.pending = {}
        self.pending_web = {}

    def start(self):
        if not hasattr(socket, 'AF_PACKET'):
            return False
        socks = []
        for name in capture_devices():
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.ntohs(0x0003))
                sock.bind((name, 0))
                sock.setblocking(False)
                socks.append(sock)
            except OSError:
                continue
        if not socks:
            return False
        threading.Thread(target=self._run, args=(socks,), daemon=True).start()
        return True

    def _run(self, socks):
        while True:
            readable, _, _ = select.select(socks, [], [], POLL)
            for sock in readable:
                try:
                    pkt = sock.recv(65535)
                except OSError:
                    continue
                ip, n = account_packet(pkt, self.ports, self.count_tcp, self.count_udp)
                if ip and n > 0:
                    wip, wn = account_packet(pkt, self.web, self.count_tcp, False) if self.web else (None, 0)
                    with self.lock:
                        self.pending[ip] = self.pending.get(ip, 0) + n
                        if wip and wn > 0:
                            self.pending_web[wip] = self.pending_web.get(wip, 0) + wn

    def drain(self):
        return self.drain_all()[0]

    def drain_all(self):
        with self.lock:
            data, web = self.pending, self.pending_web
            self.pending, self.pending_web = {}, {}
            return data, web


class ClosedWatcher:
    """`ss -E` 订阅内核的「TCP 连接关闭」事件，拿到每条连接关闭那一刻的收发字节。

    连接采样每 2 秒看一次 ss：网盘上传/下载、打开网页这种几百毫秒就结束的
    短连接，两次采样之间就断开了，以前一个字节都记不到。这里把关闭时的
    最终字节补进下一次采样。ss -E 用不了时（老内核/没权限）就只靠轮询。
    """

    def __init__(self, ports):
        self.ports = set(ports)
        self.lock = threading.Lock()
        self.closed = {}

    def start(self):
        if not shutil.which('ss'):
            return False
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def _run(self):
        commands = [['ss', '-E', '-H', '-tin'], ['ss', '-E', '-tin']]
        while True:
            for cmd in commands:
                started = time.time()
                try:
                    self._follow(cmd)
                except OSError:
                    pass
                if time.time() - started > 5:
                    break  # 跑过一阵才退出：不是参数不认识，按原命令重连
            time.sleep(30)

    def _follow(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='replace')
        header = None
        try:
            for line in proc.stdout:
                if not line.strip():
                    continue
                if not line[:1].isspace():
                    header = line.rstrip('\n')
                    continue
                if header is None:
                    continue
                flows = parse_ss(header + '\n' + line, self.ports)
                header = None
                if flows:
                    with self.lock:
                        self.closed.update(flows)
        finally:
            proc.kill()
            proc.wait()

    def drain(self):
        with self.lock:
            data = self.closed
            self.closed = {}
            return data


# Cloudflare 公布的网段。橙色云 / Tunnel 时连到本机的是这些地址，不是访客。
CLOUDFLARE = tuple(ipaddress.ip_network(n) for n in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
))


def is_cloudflare(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        ip = mapped
    return any(ip.version == net.version and ip in net for net in CLOUDFLARE)


HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'PATCH ', b'OPTIONS ')
HEADER_LIMIT = 16384


def header_ip(head):
    """反代转给网站的请求头里，经 Cloudflare 来的访客真实 IP。

    只认 CF-Connecting-IP，并用反代写的 X-Forwarded-For 最后一跳把关：
    - 最后一跳是 Cloudflare（橙色云 + 本机 Caddy/nginx）：采信；
    - 最后一跳就是 CF-Connecting-IP（Cloudflare Tunnel，cloudflared 原样转发）：采信；
    - 没有 X-Forwarded-For（cloudflared / 不加转发头的反代）：采信；
    - 最后一跳是别的地址：访客直连反代、头是自己带的。这时公网端口已经
      按真实 IP 记过一次，这里不再算，伪造的头也不会生效。
    """
    cf = xff = None
    for line in head.split(b'\r\n')[1:]:
        if not line:
            break
        name, _, value = line.partition(b':')
        name = name.strip().lower()
        if name == b'cf-connecting-ip':
            cf = value.decode('latin-1').split(',')[0].strip()
        elif name == b'x-forwarded-for':
            xff = value.decode('latin-1')
    ip = normalize_ip(cf) if cf else None
    # 请求头里的「真实 IP」不收内网地址（伪造或代理链内部的），只有网卡上看到的来访地址才收。
    if ip is not None and is_nat_ip(ip):
        ip = None
    if ip is None:
        return None
    if xff is not None:
        hop = xff.split(',')[-1].strip()
        if hop and not is_cloudflare(hop) and normalize_ip(hop) != ip:
            return None
    return str(ip)


class RealIPSniffer:
    """网站开了 Cloudflare 代理（橙色云）或 Cloudflare Tunnel 时，连到公网端口的
    全是 Cloudflare 的地址，真实访客 IP 只在 HTTP 请求头里。HTTPS 在公网上是
    加密的看不到，但本机反代（Caddy/nginx/cloudflared）转给网站程序这一段走
    回环口、是明文：这里只看回环口上指定端口的 TCP 包，从请求头取访客 IP，
    然后把这条连接后续的字节都记到这个 IP 上。只读请求头，不保存任何内容。
    同一条长连接上反代会轮流转发不同访客的请求，所以每个新请求重新认一次 IP。
    """

    IDLE = 300
    MAX_FLOWS = 4096

    def __init__(self, ports):
        self.ports = set(ports)
        self.lock = threading.Lock()
        self.flows = {}
        self.pending = {}
        self.seen = {}
        self.requests = 0

    def start(self):
        if not hasattr(socket, 'AF_PACKET'):
            return False
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.ntohs(0x0003))
            sock.bind(('lo', 0))
        except OSError:
            return False
        threading.Thread(target=self._run, args=(sock,), daemon=True).start()
        return True

    def _run(self, sock):
        outgoing = getattr(socket, 'PACKET_OUTGOING', 4)
        last_gc = time.time()
        while True:
            try:
                pkt, addr = sock.recvfrom(65535)
            except OSError:
                time.sleep(1)
                continue
            # 回环口上每个包会出现两次（发出 + 收到），只数收到的那次。
            if len(addr) > 2 and addr[2] == outgoing:
                continue
            now = time.time()
            try:
                self.feed(pkt, now)
            except Exception:
                pass
            if now - last_gc > 60:
                last_gc = now
                self.gc(now)

    def feed(self, pkt, now):
        parsed = parse_ip_packet(pkt)
        if not parsed or parsed[0] != 6 or len(parsed[3]) < 20:
            return
        _proto, src, dst, l4, total = parsed
        sport, dport = struct.unpack('!HH', l4[:4])
        ports = self.ports
        if dport in ports:
            key, to_server = (src, sport, dport), True
        elif sport in ports:
            key, to_server = (dst, dport, sport), False
        else:
            return
        payload = l4[(l4[12] >> 4) * 4:]
        flags = l4[13]
        flow = self.flows.get(key)
        if to_server and payload:
            if flow is not None and flow[2] is not None:
                flow[2] += payload
                flow[3] += total
                total = self._finish_header(flow, total)
            elif payload.startswith(HTTP_METHODS):
                if flow is None:
                    if len(self.flows) >= self.MAX_FLOWS:
                        self.gc(now, force=True)
                    flow = self.flows[key] = [None, now, None, 0]
                flow[0], flow[2], flow[3] = None, bytearray(payload), total
                total = self._finish_header(flow, total)
        if flow is None:
            return
        flow[1] = now
        ip = flow[0]
        if ip and total > 0:
            with self.lock:
                self.pending[ip] = self.pending.get(ip, 0) + total
                self.seen[ip] = now
        if flags & 0x05:  # FIN / RST
            self.flows.pop(key, None)

    def _finish_header(self, flow, total):
        """请求头收齐了就认 IP，返回这个包要记的字节（含之前攒着的请求头包）。"""
        buf = flow[2]
        end = buf.find(b'\r\n\r\n')
        if end < 0 and len(buf) < HEADER_LIMIT:
            return 0
        flow[0] = header_ip(bytes(buf[:end if end >= 0 else HEADER_LIMIT]))
        flow[2], total, flow[3] = None, flow[3], 0
        if flow[0]:
            with self.lock:
                self.requests += 1
        return total

    def gc(self, now, force=False):
        idle = self.IDLE // 10 if force else self.IDLE
        for key in [k for k, v in self.flows.items() if now - v[1] > idle]:
            self.flows.pop(key, None)

    def drain(self):
        """返回 ({ip: 字节}, {ip: 最后一个包的时间}, 认出的请求数)。"""
        with self.lock:
            data, seen, n = self.pending, self.seen, self.requests
            self.pending, self.seen, self.requests = {}, {}, 0
            return data, seen, n


def backend_ports(text=None):
    """本机非代理、非 SSH 进程的 TCP 监听端口（含只绑 127.0.0.1 的）。反代
    就是把请求转给这些端口，在回环口上看这些端口就能读到转发头。"""
    sockets = iter_sockets(read_socket_table() if text is None else text)
    return sorted({
        item['port'] for item in sockets
        if item['proto'] == 'tcp' and item['port'] != 22
        and not item['name'].startswith('sshd') and not PROXY_PROCESS.search(item['line'])
    })


def start_sniffer(config):
    if not config.get('realip', True):
        return None
    try:
        sniffer = RealIPSniffer(backend_ports())
    except Exception:
        return None
    if not sniffer.start():
        print('liuliang: 回环口抓包不可用，Cloudflare 后面的网站访客只能看到 Cloudflare 的 IP', file=sys.stderr, flush=True)
        return None
    return sniffer


def save_realip(c, sniffer, now):
    """把回环口认出的访客字节写进 pending（全部算网站流量）。"""
    if sniffer is None:
        return
    data, seen, requests = sniffer.drain()
    for ip, n in data.items():
        add_pending(c, {ip: n}, seen.get(ip, now), {ip: n})
    if requests or data:
        c.execute("INSERT OR REPLACE INTO metadata VALUES('realip_last',?)", (str(now),))


def flow_port(key):
    """流的 key 里取本机服务端口：tcp|本机|端口|对端|端口，ctcp/udp|源|端口|目的|端口。"""
    parts = str(key).split('|')
    try:
        return int(parts[2] if parts[0] == 'tcp' else parts[4])
    except (IndexError, ValueError):
        return None


def web_activity(previous, current, web, now):
    """只看网站端口上的流，算出每个 IP 的网站字节（已包含在总字节里）。"""
    if not web:
        return {}
    web = set(web)
    pick = lambda d: {k: v for k, v in d.items() if flow_port(k) in web}
    return account_flows(pick(previous), pick(current), now)[1]


def account_flows(previous, current, now):
    """previous: key -> (up, down, seen)。current: key -> (ip, up, down)。"""
    activity = {}
    for key, (ip, up, down) in current.items():
        old = previous.get(key)
        old_up, old_down = (old[0], old[1]) if old else (0, 0)
        du = up - old_up if up >= old_up else up
        dd = down - old_down if down >= old_down else down
        total = du + dd
        if total > 0 and ip:
            activity[ip] = activity.get(ip, 0) + total
    if not current and previous:
        return previous, activity
    baselines = {key: (up, down, now) for key, (_ip, up, down) in current.items()}
    for key, old in previous.items():
        if key not in baselines and now - old[2] <= FLOW_KEEP:
            baselines[key] = old
    return baselines, activity


def load_flows(c):
    return {key: (up, down, seen) for key, up, down, seen in c.execute('SELECT key,up,down,seen FROM flows')}


def save_flows(c, baselines):
    c.execute('DELETE FROM flows')
    if baselines:
        c.executemany(
            'INSERT INTO flows(key,up,down,seen) VALUES(?,?,?,?)',
            [(key, up, down, seen) for key, (up, down, seen) in baselines.items()],
        )


def add_pending(c, activity, now, web=None):
    """now 是这批流量的最后时间（last_seen）。"""
    web = web or {}
    for ip, n in activity.items():
        if n <= 0:
            continue
        c.execute(
            'INSERT INTO pending(ip,bytes,last_seen,web) VALUES(?,?,?,?) '
            'ON CONFLICT(ip) DO UPDATE SET bytes=pending.bytes+excluded.bytes, '
            'web=pending.web+excluded.web, '
            'last_seen=max(pending.last_seen, excluded.last_seen)',
            (ip, int(n), now, int(min(max(web.get(ip, 0), 0), n))),
        )


def take_pending(c, now):
    rows = list(c.execute('SELECT ip,bytes,last_seen,web FROM pending WHERE bytes>0'))
    for ip, n, seen, web in rows:
        c.execute('INSERT INTO traffic(ts,ip,bytes,web) VALUES(?,?,?,?)', (now, ip, int(n), int(min(web or 0, n))))
        c.execute(
            'INSERT INTO clients(ip,last_seen) VALUES(?,?) '
            'ON CONFLICT(ip) DO UPDATE SET last_seen=max(clients.last_seen, excluded.last_seen)',
            (ip, seen),
        )
    c.execute('DELETE FROM pending')
    c.execute('DELETE FROM traffic WHERE ts<?', (now - 8 * 86400,))
    c.execute('DELETE FROM clients WHERE last_seen<?', (now - 8 * 86400,))


def read_flow_snapshot(ports, sources):
    flows = {}
    if sources.get('tcp') == 'ss':
        flows.update(parse_ss(read_ss() or '', ports))
    want_tcp = sources.get('tcp') == 'conntrack'
    want_udp = sources.get('udp') == 'conntrack'
    if want_tcp or want_udp:
        flows.update(parse_conntrack(conntrack_text() or '', ports, tcp=want_tcp, udp=want_udp))
    return flows


def diag_tick(config, flush, pump=None, watcher=None, sniffer=None, sites=None):
    ports = config['ports']
    sources = config.get('diag') or {}
    now = time.time()
    with open(LOCK, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = read_flow_snapshot(ports, sources)
        if watcher is not None:
            # 两次采样之间已经关掉的连接：用关闭时的最终字节，跟基线相减只补差额。
            current.update(watcher.drain())
        c = open_db()
        try:
            prev = load_flows(c)
            baselines, activity = account_flows(prev, current, now)
            web = web_activity(prev, current, config.get('web'), now)
            if pump is not None:
                raw, raw_web = pump.drain_all()
                for ip, n in raw.items():
                    if n > 0:
                        activity[ip] = activity.get(ip, 0) + n
                for ip, n in raw_web.items():
                    if n > 0:
                        web[ip] = web.get(ip, 0) + n
            # 从已经有流量记录的 nft 安装切过来时，套接字上的历史字节不要再加一遍。
            if not prev and c.execute('SELECT 1 FROM traffic LIMIT 1').fetchone():
                activity = {}
            save_flows(c, baselines)
            add_pending(c, activity, now, web)
            save_realip(c, sniffer, now)
            if flush:
                take_pending(c, now)
                save_sites(c, sites, now)
                save_nic(c, now)
                c.execute("INSERT OR REPLACE INTO metadata VALUES('sample',?)", (str(now),))
            c.commit()
        finally:
            c.close()


def follow_ports(config, seen):
    """后台重新检测监听端口。连续两次都在、但还没统计的端口并入配置。

    seen 是上一次检测到的端口集合（调用方保存）。返回 (这次的集合, 是否有新端口)。
    手动 --ports 安装的（auto=False）不自动加。已有端口一个不删。
    """
    if not config.get('auto', True):
        return seen, False
    try:
        detected, _mode, service = scan_ports(True)
    except Exception:
        return seen, False
    now = set(detected)
    fresh = sorted((now & seen) - set(config['ports']))
    web_fresh = sorted((set(service) & seen & (set(config['ports']) | set(fresh))) - set(config.get('web') or []))
    room = 64 - len(config['ports'])
    fresh = fresh[:max(room, 0)]
    if not fresh and not web_fresh:
        return now, False
    config['ports'] = sorted(set(config['ports']) | set(fresh))
    config['web'] = sorted((set(config.get('web') or []) | set(web_fresh)) & set(config['ports']))
    # 用户在后台运行期间用命令改过的选项（计费方式、日志）以硬盘上的为准，不要被旧值盖掉。
    try:
        disk = json.loads(CONFIG.read_text())
        for key in ('billing', 'log', 'reset_day'):
            if key in disk:
                config[key] = disk[key]
    except (OSError, ValueError):
        pass
    CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
    CONFIG.chmod(0o600)
    print('liuliang: 新检测到端口 ' + ','.join(map(str, fresh or web_fresh)) + '，已并入统计', file=sys.stderr, flush=True)
    return now, True


def reload_nft(config):
    """端口变了：先把旧表里的计数落盘，再换表，并清掉基线（新表从 0 数起）。"""
    text = rules(config['ports'], config.get('web') or [])
    collect(dict(config, geo=False))
    with open(LOCK, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if apply_nft(text):
            clear_counters()


def diag_daemon(config):
    sources = config.get('diag') or {}
    pump = None
    watcher = None
    if sources.get('tcp') == 'ss':
        watcher = ClosedWatcher(config['ports'])
        if not watcher.start():
            watcher = None
    if sources.get('tcp') == 'raw' or sources.get('udp') == 'raw':
        pump = PacketPump(config['ports'], sources.get('tcp') == 'raw', sources.get('udp') == 'raw', config.get('web') or [])
        try:
            if not pump.start():
                print('liuliang: 抓包没有权限，原始计数未启动', file=sys.stderr, flush=True)
                pump = None
        except OSError as exc:
            print('liuliang: ' + str(exc), file=sys.stderr, flush=True)
            pump = None
    sniffer = start_sniffer(config)
    sites = start_sites(config)
    last = 0
    scanned, seen = 0, set()
    while True:
        try:
            now = time.time()
            if now - scanned >= RESCAN:
                scanned = now
                refresh_sniffer(sniffer)
                seen, changed = follow_ports(config, seen)
                if changed:
                    if watcher is not None:
                        watcher.ports = set(config['ports'])
                    if pump is not None:
                        pump.ports, pump.web = set(config['ports']), set(config.get('web') or [])
                    if sites is not None:
                        sites.set_ports(config['ports'])
            flush = now - last >= INTERVAL
            diag_tick(config, flush, pump, watcher, sniffer, sites)
            if flush:
                last = now
                if config.get('geo', True):
                    geo_resolve()
        except Exception as exc:
            print('liuliang:', str(exc), file=sys.stderr, flush=True)
        time.sleep(POLL)


def refresh_sniffer(sniffer):
    """网站换了端口 / 后装的网站：回环口要看的端口跟着变。"""
    if sniffer is None:
        return
    try:
        sniffer.ports = set(backend_ports())
    except Exception:
        pass


# ---- 每个 IP 访问了哪些应用/网站 ----
# 代理程序（Xray / V2Ray / sing-box）的访问日志里写着「哪个客户端 IP:端口 要连哪个
# 域名」。同一条 TCP 连接在 ss 里能看到收发字节，按「客户端 IP:端口」对上，就知道
# 每个域名用了多少流量。hy2/tuic 这类 UDP 协议、开了 mux 的连接是多个网站共用一条
# 连接，只能记下访问次数，流量在报表里算进「其他」。只记域名，不记网址和内容。
SITE_KEEP = 600      # 日志里认到、但 ss 里一直没看到的连接，对应关系留这么久
SITE_GRACE = 15      # 连接关了、日志还没读到时，关闭时的字节先等这么久
SITE_RESCAN = 300    # 每隔这么久重新找一次代理的访问日志（代理重启、换了配置）
SITE_PROCESS = re.compile(r'(xray|v2ray|sing-box)', re.I)
SITE_MANUAL = ('Xray/V2Ray 配置里写 "log": {"access": "/var/log/xray/access.log"}（不能是 none），'
               'sing-box 配置里 "log": {"level": "info"}，改完重启代理。')
SITE_HELP = ('解决办法：在 VPS 上运行 liuliang --enable-log，自动打开代理的访问记录（会先备份原配置，代理重启几秒），'
             '过几分钟再来看。想自己改的话：' + SITE_MANUAL)

# 常见应用的域名后缀。没列出的网站按主域名（如 example.com）归类。
APPS = (
    ('YouTube', 'youtube.com youtu.be googlevideo.com ytimg.com youtube-nocookie.com youtubei.googleapis.com youtubekids.com yt3.ggpht.com'),
    ('Netflix', 'netflix.com netflix.net nflxvideo.net nflximg.net nflximg.com nflxext.com nflxso.net'),
    ('TikTok', 'tiktok.com tiktokv.com tiktokv.us tiktokcdn.com tiktokcdn-us.com byteoversea.com ibytedtos.com ibyteimg.com muscdn.com musical.ly'),
    ('Instagram', 'instagram.com cdninstagram.com'),
    ('Threads', 'threads.net threads.com'),
    ('Facebook', 'facebook.com facebook.net fbcdn.net fb.com fbsbx.com messenger.com'),
    ('WhatsApp', 'whatsapp.com whatsapp.net wa.me'),
    ('Telegram', 'telegram.org telegram.me t.me telesco.pe cdn-telegram.org tdesktop.com'),
    ('X (Twitter)', 'twitter.com x.com twimg.com t.co'),
    ('ChatGPT', 'openai.com chatgpt.com oaistatic.com oaiusercontent.com'),
    ('Claude', 'claude.ai claude.com anthropic.com'),
    ('Gemini', 'gemini.google.com bard.google.com'),
    ('Google', 'google.com google.com.hk googleapis.com gstatic.com googleusercontent.com ggpht.com gvt1.com gvt2.com '
               'googlesyndication.com doubleclick.net googletagmanager.com google-analytics.com app-measurement.com'),
    ('GitHub', 'github.com githubusercontent.com githubassets.com github.io'),
    ('Discord', 'discord.com discord.gg discordapp.com discordapp.net discord.media'),
    ('Reddit', 'reddit.com redd.it redditmedia.com redditstatic.com'),
    ('Wikipedia', 'wikipedia.org wikimedia.org'),
    ('Spotify', 'spotify.com scdn.co spotifycdn.com spotifycdn.net'),
    ('Twitch', 'twitch.tv ttvnw.net jtvnw.net'),
    ('Disney+', 'disneyplus.com disney-plus.net dssott.com bamgrid.com'),
    ('HBO Max', 'max.com hbomax.com'),
    ('Prime Video', 'primevideo.com aiv-cdn.net aiv-delivery.net amazonvideo.com'),
    ('Amazon', 'amazon.com amazonaws.com media-amazon.com ssl-images-amazon.com'),
    ('Apple', 'apple.com icloud.com icloud-content.com mzstatic.com apple-cloudkit.com cdn-apple.com aaplimg.com'),
    ('Microsoft', 'microsoft.com live.com office.com office.net outlook.com bing.com msn.com skype.com windowsupdate.com msftconnecttest.com'),
    ('Steam', 'steampowered.com steamcommunity.com steamstatic.com steamcontent.com steamserver.net'),
    ('PlayStation', 'playstation.com playstation.net sonyentertainmentnetwork.com'),
    ('LINE', 'line.me line-scdn.net line-apps.com'),
    ('Signal', 'signal.org whispersystems.org'),
    ('Zoom', 'zoom.us zoom.com'),
    ('Pixiv', 'pixiv.net pximg.net'),
    ('Pinterest', 'pinterest.com pinimg.com'),
    ('LinkedIn', 'linkedin.com licdn.com'),
    ('Snapchat', 'snapchat.com sc-cdn.net snapkit.com'),
    ('Bilibili', 'bilibili.com bilivideo.com hdslb.com biliapi.net'),
    ('Speedtest', 'speedtest.net ookla.com'),
    ('Cloudflare', 'cloudflare.com cloudflare-dns.com'),
)
APP_SUFFIX = {suffix: name for name, suffixes in APPS for suffix in suffixes.split()}
# Telegram 客户端多数直接连 IP，日志里没有域名。
TELEGRAM_NETS = tuple(ipaddress.ip_network(n) for n in (
    '91.105.192.0/23', '91.108.4.0/22', '91.108.8.0/22', '91.108.12.0/22', '91.108.16.0/22',
    '91.108.20.0/22', '91.108.56.0/22', '95.161.64.0/20', '149.154.160.0/20', '185.76.151.0/24',
    '2001:67c:4e8::/48', '2001:b28:f23c::/47', '2001:b28:f23f::/48', '2a0a:f280::/32',
))


def base_domain(host):
    """主域名：www.example.com -> example.com，a.b.example.co.uk -> example.co.uk。"""
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in ('co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ne', 'or', 'go'):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def site_label(host):
    """域名/IP 归到哪个应用或网站。"""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return 'Telegram' if any(ip.version == n.version and ip in n for n in TELEGRAM_NETS) else host
    parts = host.split('.')
    for i in range(len(parts) - 1):
        name = APP_SUFFIX.get('.'.join(parts[i:]))
        if name:
            return name
    return base_domain(host)


def clean_host(text):
    """日志里的目标地址只留可打印字符，防止终端控制字符混进报表。"""
    host = ''.join(ch for ch in str(text or '') if ch.isprintable() and not ch.isspace())
    return host.strip('[]').rstrip('.').lower()[:253]


def split_target(token):
    return split_host_port(re.sub(r'^(?:tcp|udp):', '', token))


ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
XRAY_ACCEPT = re.compile(r'(\S+)\s+accepted\s+(\S+)')
SINGBOX_CONN = re.compile(r'\[(\d+)[^\]]*\]\s+inbound/[^:]*:\s+inbound (?:packet )?connection (from|to) (\S+)')


class AccessParser:
    """读 Xray/V2Ray 和 sing-box 的访问日志，认出 (客户端 IP, 客户端端口, 目标域名)。

    Xray：2024/05/01 12:00:00 from 1.2.3.4:5678 accepted tcp:www.youtube.com:443 [in -> out]
    sing-box 分两行，用连接编号对上：
      [3856612376 0ms] inbound/vless[in]: inbound connection from 1.2.3.4:5678
      [3856612376 0ms] inbound/vless[in]: inbound connection to www.youtube.com:443
    """

    def __init__(self):
        self.pending = {}

    def feed(self, line):
        line = ANSI.sub('', line)
        found = XRAY_ACCEPT.search(line)
        if found:
            return self._event(found.group(1), found.group(2))
        found = SINGBOX_CONN.search(line)
        if not found:
            return None
        cid, way, addr = found.groups()
        if way == 'from':
            if len(self.pending) >= 4096:
                self.pending.pop(next(iter(self.pending)))
            self.pending[cid] = addr
            return None
        src = self.pending.pop(cid, None)
        return self._event(src, addr) if src else None

    def _event(self, src, dst):
        src_host, src_port = split_target(src)
        dst_host, dst_port = split_target(dst)
        # 53 端口是 DNS 查询，不算访问网站。
        if src_host is None or dst_host is None or dst_port == 53:
            return None
        ip = normalize_ip(src_host)
        host = clean_host(dst_host)
        if ip is None or not host:
            return None
        return str(ip), src_port, host


def load_json(path):
    """读代理配置。Xray 允许 // 注释，读不出来时去掉注释行再试一次。"""
    try:
        text = Path(path).read_text(errors='replace')
    except OSError:
        return None
    for attempt in (text, re.sub(r'^\s*//.*$', '', text, flags=re.M)):
        try:
            data = json.loads(attempt)
        except ValueError:
            continue
        return data if isinstance(data, dict) else None
    return None


def proxy_processes():
    """正在运行的 Xray/V2Ray/sing-box：[(pid, 种类, 命令行)]。"""
    found = []
    for d in Path('/proc').glob('[0-9]*'):
        try:
            argv = [a.decode(errors='replace') for a in (d / 'cmdline').read_bytes().split(b'\0') if a]
        except OSError:
            continue
        hit = SITE_PROCESS.search(os.path.basename(argv[0])) if argv else None
        if hit:
            found.append((d.name, hit.group(1).lower(), argv))
    return found


def proxy_configs(kind, argv, cwd):
    """命令行里的配置文件（-c / -config / -confdir / -C），没写时用默认位置。返回 (文件, 工作目录)。"""
    files = []
    args = argv[1:]
    for i, arg in enumerate(args):
        if arg in ('-D', '--directory') and i + 1 < len(args):
            cwd = os.path.join(cwd, args[i + 1])
    i = 0
    while i < len(args):
        key, eq, value = args[i].partition('=')
        if key in ('-c', '-config', '--config', '-C', '-confdir', '--confdir', '--config-directory'):
            if not eq:
                i += 1
                value = args[i] if i < len(args) else ''
            path = Path(cwd, value)
            if key in ('-C', '-confdir', '--confdir', '--config-directory'):
                files += sorted(path.glob('*.json')) if path.is_dir() else []
            elif value:
                files.append(path)
        i += 1
    if not files:
        defaults = {
            'xray': ['/usr/local/etc/xray/config.json', '/etc/xray/config.json'],
            'v2ray': ['/usr/local/etc/v2ray/config.json', '/etc/v2ray/config.json'],
            'sing-box': [os.path.join(cwd, 'config.json'), '/etc/sing-box/config.json'],
        }[kind]
        files = [Path(p) for p in defaults if Path(p).is_file()][:1]
    return files, cwd


def service_unit(pid):
    """进程属于哪个 systemd 服务；它的终端输出在 journald 里。"""
    try:
        text = Path('/proc/%s/cgroup' % pid).read_text()
    except OSError:
        return None
    found = re.findall(r'/([^/\s]+\.service)', text)
    return found[-1] if found else None


PROXY_NAMES = {'xray': 'Xray', 'v2ray': 'V2Ray', 'sing-box': 'sing-box'}
PANEL = re.compile(r'(x-ui|3x-ui|s-ui|h-ui|marzban|hiddify|v2board|xrayr|v2bx)', re.I)
# liuliang --enable-log 打开的访问日志写在这里。文件由 liuliang 读完后定期清空，不会越写越大。
ACCESS_DIR = Path('/var/log/liuliang-access')
ACCESS_LOG = ACCESS_DIR / 'access.log'
ACCESS_MAX = 20 * 1024 * 1024
# 小内存机器（内存 ≤128MB）上，日志文件超过 5MB 就清空，少占硬盘、少读数据。
ACCESS_MAX_SMALL = 5 * 1024 * 1024


# 名词小词典：MemTotal = 这台机器的总内存（/proc/meminfo 里那一行，单位 KB）。
# 名词小词典：tty = 你正在打字的那个终端。用 curl … | sh 安装时，标准输入是下载的脚本，
# 不是键盘，所以提问要直接去终端（/dev/tty）读；连终端都没有时才用默认值，并说一声。
TTY = '/dev/tty'


def has_tty():
    try:
        with open(TTY):
            return True
    except OSError:
        return False


def ask(prompt, default=''):
    """问一个问题，从终端读一行；没有终端就打印提示、返回默认值。"""
    try:
        # 终端不能「读写同开」（不支持 seek，会报错），所以读、写分开打开。
        with open(TTY, 'w') as out, open(TTY) as inp:
            out.write(prompt); out.flush()
            line = inp.readline()
            return line.strip() if line else default
    except OSError:
        print(prompt + '（没有终端可以输入，用默认值）')
        return default
    except KeyboardInterrupt:
        return default


def mem_mb():
    """返回机器总内存（MB），读不到返回 0。"""
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemTotal:'):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


# 安装时要不要自动打开代理访问日志：
# 用户明确说过（--log yes/no 或之前选过）就照用户的；
# 否则默认打开，内存小于 48MB 的机器默认不开，免得代理多写日志拖慢机器。
def log_action(explicit, choice):
    """安装时读不到访问记录怎么办：用户明确选过就照办（enable/skip），没选过就问（ask）。"""
    if explicit:
        return 'enable' if choice == 'yes' else 'skip'
    return 'ask'


def auto_log_choice(arg, existing, mem):
    if arg in ('yes', 'no'):
        return arg
    old = (existing or {}).get('log')
    if old in ('yes', 'no'):
        return old
    return 'no' if 0 < mem < 48 else 'yes'


def access_cap(mem=None):
    """日志清空门槛：小内存机器用 5MB，其他 20MB。"""
    mem = mem_mb() if mem is None else mem
    return ACCESS_MAX_SMALL if 0 < mem <= 128 else ACCESS_MAX


def proc_status(pid):
    try:
        text = Path('/proc/%s/status' % pid).read_text()
    except OSError:
        return {}
    return dict(line.split(':', 1) for line in text.splitlines() if ':' in line)


def panel_name(pid, argv):
    """代理是不是由面板（x-ui / 3x-ui / Marzban 等）启动的，是的话返回面板名。"""
    ppid = proc_status(pid).get('PPid', '').strip()
    try:
        parent = Path('/proc/%s/comm' % ppid).read_text().strip() if ppid else ''
    except OSError:
        parent = ''
    for text in (parent, argv[0] if argv else ''):
        found = PANEL.search(text)
        if found:
            return found.group(1)
    return None


def output_target(pid, fd):
    """进程的标准输出/错误指向哪里：文件路径、/dev/null、pipe:[..]、socket:[..]。"""
    try:
        return os.readlink('/proc/%s/fd/%d' % (pid, fd))
    except OSError:
        return ''


def docker_log(pid):
    """Docker 容器里的代理：终端输出在 /var/lib/docker/containers/<id>/<id>-json.log。"""
    try:
        text = Path('/proc/%s/cgroup' % pid).read_text()
    except OSError:
        return None
    for cid in re.findall(r'[0-9a-f]{64}', text):
        path = Path('/var/lib/docker/containers', cid, cid + '-json.log')
        if path.is_file():
            return str(path)
    return None


def systemd_running():
    return Path('/run/systemd/system').is_dir()


def proxy_log(pid, kind, argv):
    """一个代理进程的访问日志在哪。返回 (来源或 None, 说明, 配置文件, 工作目录, 日志设置)。

    来源是 ('file', 路径) 或 ('journal', 服务名)。说明用大白话写给不懂配置的人看。
    """
    try:
        cwd = os.readlink('/proc/%s/cwd' % pid)
    except OSError:
        cwd = '/'
    files, cwd = proxy_configs(kind, argv, cwd)
    log = {}
    for path in files:
        data = load_json(path)
        if data and isinstance(data.get('log'), dict):
            log.update(data['log'])
    name = PROXY_NAMES[kind]
    if kind == 'sing-box':
        level = str(log.get('level') or 'info').lower()
        if log.get('disabled'):
            return None, 'sing-box 把日志关掉了（log.disabled），所以看不到访问了哪些网站', files, cwd, log
        if level in ('warn', 'warning', 'error', 'fatal', 'panic'):
            return None, 'sing-box 日志级别是 ' + level + '，这个级别不记访问了哪些网站（要 info）', files, cwd, log
        target, fd = str(log.get('output') or ''), 2
    else:
        target, fd = str(log.get('access') or ''), 1
        if target.lower() == 'none':
            panel = panel_name(pid, argv)
            if panel:
                return None, (name + ' 由 ' + panel + ' 面板管理，面板里把「访问日志」关掉了（none）。请在面板的 Xray 设置 → 日志 → '
                              '访问日志里选 ./access.log 并保存重启，liuliang 会自动读取'), files, cwd, log
            return None, name + ' 把访问记录关掉了（log.access 为 none），所以看不到访问了哪些网站', files, cwd, log
    if target:
        # 文件还不存在也先记下（代理第一次写时才创建）；「是不是真有访问记录」由 has_access_lines 判断。
        return ('file', os.path.join(cwd, target)), '', files, cwd, log
    # 配置里没写日志文件：访问记录输出到终端。看终端输出最后去了哪里。
    out = output_target(pid, fd) or output_target(pid, 3 - fd)
    if out.startswith('/') and not out.startswith('/dev/') and os.path.isfile(out):
        return ('file', out), '', files, cwd, log
    if out == '/dev/null':
        return None, name + ' 的访问记录直接被丢掉了（输出到 /dev/null），没有保存', files, cwd, log
    docker = docker_log(pid)
    if docker:
        return ('file', docker), '', files, cwd, log
    panel = panel_name(pid, argv)
    if panel:
        return None, (name + ' 由 ' + panel + ' 面板启动，访问记录被面板接走了。请在面板的 Xray 设置 → 日志 → '
                      '访问日志里选 ./access.log 并保存重启，liuliang 会自动读取'), files, cwd, log
    unit = service_unit(pid)
    if unit and shutil.which('journalctl') and systemd_running():
        return ('journal', unit), '', files, cwd, log
    return None, name + ' 没有把访问记录保存下来（没写进文件，也没有 systemd 日志）', files, cwd, log


def has_access_lines(source, kind=None):
    """日志里真的有访问记录才算能读到：文件要存在且最近 256KB 里有访问行；
    systemd 日志看最近 300 行。只配了路径、或者只有 warning 报错行，都不算。"""
    parser = AccessParser()
    # liuliang 自己打开的那个日志：要代理配置里真的写着这个文件才算开好了（刚开时可能还是空的）。
    # 只看目录/文件在不在不行：删掉代理的日志设置后，旧目录还留着。
    if source[0] == 'file' and source[1] == str(ACCESS_LOG):
        if ours_configured():
            return True
    try:
        if source[0] == 'file':
            with open(source[1], 'rb') as f:
                f.seek(0, 2); f.seek(max(0, f.tell() - (256 << 10)))
                text = f.read().decode('utf-8', 'replace')
        else:
            text = subprocess.run(['timeout', '10', 'journalctl', '-u', source[1], '-n', '300', '--no-pager', '-o', 'cat'],
                                  capture_output=True, text=True).stdout
    except OSError:
        return False
    return any(parser.feed(line) for line in text.splitlines())


def ours_configured():
    """有没有正在运行的代理，配置里把访问日志写到 liuliang 的文件。"""
    for pid, kind, argv in proxy_processes():
        try:
            if proxy_log(pid, kind, argv)[0] == ('file', str(ACCESS_LOG)):
                return True
        except Exception:
            continue
    return False


def site_sources(extra=()):
    """找代理的访问日志。返回 (来源, 说明)：来源是 ('file', 路径) 或 ('journal', 服务名)。"""
    sources = [('file', str(p)) for p in extra]
    if ACCESS_LOG.exists():
        sources.append(('file', str(ACCESS_LOG)))
    notes = []
    for pid, kind, argv in proxy_processes():
        source, note, _files, _cwd, _log = proxy_log(pid, kind, argv)
        if source:
            sources.append(source)
        elif note:
            notes.append(note)
    seen = set()
    sources = [s for s in sources if not (s in seen or seen.add(s))]
    notes = [n for n in notes if not (n in seen or seen.add(n))]
    return sources, notes


def can_enable(sources, notes):
    """读不到访问记录、又不是面板管理的（面板要在面板里开），--enable-log 能帮上忙。"""
    # 只要有一个来源里真的有访问记录就不用开；只是配了路径/只有报错行的不算。
    return not any(has_access_lines(x) for x in sources) and (not notes or any('面板' not in n for n in notes))


def check_config(kind, exe, argv, cwd):
    """改完配置先让代理自己检查一遍，不通过就还原，避免代理起不来。"""
    args = list(argv[1:])
    if kind == 'sing-box':
        if 'run' in args:
            args[args.index('run')] = 'check'
        else:
            args.insert(0, 'check')
    else:
        args.append('-test')
    try:
        out = subprocess.run([exe] + args, cwd=cwd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    text = (out.stdout + out.stderr).strip().splitlines()
    return out.returncode == 0, (text[-1] if text else '')


# 名词小词典：服务 = 让代理开机自启、挂了自动拉起的那个启动文件；
# OpenRC 在 /etc/init.d/，systemd 在 /etc/systemd/system/ 等目录。
# 一键脚本常用 xray-node-1、sing-box-xxx 这类名字，所以按「启动文件里写着这个配置文件路径」来找。
SERVICE_DIRS = ('/etc/init.d', '/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system')
SERVICE_NAME = re.compile(r'(xray|v2ray|sing-?box|hysteria|node)', re.I)


def services_for_config(config, dirs=SERVICE_DIRS):
    """返回启动文件里写着这个配置路径的服务：[('openrc'|'systemd', 名字)]。"""
    found = []
    config = str(config)
    for d in dirs:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            path = os.path.join(d, name)
            if not SERVICE_NAME.search(name) or not os.path.isfile(path):
                continue
            try:
                text = Path(path).read_text(errors='replace')
            except OSError:
                continue
            # 写着这个配置文件；或者用 -confdir 指向它所在的目录（目录太通用如 /etc 不算）。
            folder = os.path.dirname(config)
            if config in text or (folder not in ('', '/', '/etc', '/root', '/usr/local/etc') and re.search(re.escape(folder) + r'/?["\s]', text)):
                if 'init.d' in d:
                    found.append(('openrc', name))
                elif name.endswith('.service'):
                    found.append(('systemd', name))
    seen = set()
    return [x for x in found if not (x in seen or seen.add(x))]


# 名词小词典：pidfile = 服务启动后把进程号写进去的文件（如 /run/xray-node-1.pid），
# OpenRC 靠它认出「这个进程归哪个服务管」。
def proc_parents(pid, proc='/proc'):
    """这个进程和它的上级进程号（一直到 1），用来对 pidfile：服务可能先起一个外壳再起 xray。"""
    chain, seen = [], set()
    pid = str(pid)
    while pid and pid not in ('0', '1') and pid not in seen:
        seen.add(pid); chain.append(pid)
        try:
            status = Path(proc, pid, 'status').read_text()
        except OSError:
            break
        found = re.search(r'^PPid:\s*(\d+)', status, re.M)
        pid = found.group(1) if found else ''
    return chain


def services_for_pid(pid, config=None, initd='/etc/init.d', proc='/proc', unitdirs=SERVICE_DIRS[1:]):
    """找管着这个代理进程的服务：
    1. OpenRC 启动文件里的 pidfile，里面的进程号是它自己或它的上级；
    2. 名字约定：配置在 /etc/xray-node/nodes/<N>/ 下 → 服务 xray-node-<N>（VPS-dajianjiedian 一键脚本）。"""
    found = []
    chain = set(proc_parents(pid, proc))
    try:
        names = sorted(os.listdir(initd))
    except OSError:
        names = []
    for name in names:
        try:
            text = Path(initd, name).read_text(errors='replace')
        except OSError:
            continue
        got = re.search(r'^\s*pidfile=["\']?([^"\'\s]+)', text, re.M)
        if not got or '$' in got.group(1):
            continue
        try:
            if Path(got.group(1)).read_text().strip() in chain:
                found.append(('openrc', name))
        except OSError:
            continue
    node = re.search(r'/xray-node/nodes/(\d+)/', str(config or ''))
    if node and not found:
        svc = 'xray-node-' + node.group(1)
        if svc in names:
            found.append(('openrc', svc))
        for d in unitdirs:
            for unit in (svc + '.service', 'xray-node@.service'):
                if os.path.isfile(os.path.join(d, unit)):
                    found.append(('systemd', svc + '.service' if unit.startswith(svc) else 'xray-node@%s.service' % node.group(1)))
    seen = set()
    return [x for x in found if not (x in seen or seen.add(x))]


def restart_proxy(pid, kind, config=None):
    """重启代理让新日志设置生效。返回 None 表示已重启，否则返回要用户自己做的事。"""
    # 先找「启动文件里写着这个配置」的服务，有几个就全重启。
    owners = services_for_pid(pid, config)
    owners += [x for x in (services_for_config(config) if config else []) if x not in owners]
    done = 0
    for init, name in owners:
        if init == 'systemd' and systemd_running():
            subprocess.run(['timeout', '60', 'systemctl', 'restart', name], check=True, capture_output=True, text=True); done += 1
        elif init == 'openrc' and shutil.which('rc-service'):
            subprocess.run(['timeout', '60', 'rc-service', name, 'restart'], check=True, capture_output=True, text=True); done += 1
    if done:
        # 确认真的重启了：原来那个进程号应该没了。
        for _ in range(20):
            if not Path('/proc', str(pid)).exists():
                break
            time.sleep(0.5)
        print('  已重启服务：' + '、'.join(n for _i, n in owners) + ('（进程号已更换）' if not Path('/proc', str(pid)).exists() else '（旧进程还在，请稍后用 liuliang --doctor 看一下）'))
        return None
    unit = service_unit(pid)
    if unit and systemd_running():
        subprocess.run(['systemctl', 'restart', unit], check=True, capture_output=True, text=True)
        return None
    if Path('/etc/init.d', kind).exists() and shutil.which('rc-service'):
        subprocess.run(['rc-service', kind, 'restart'], check=True, capture_output=True, text=True)
        return None
    if docker_log(pid):
        return '代理在 Docker 容器里，请重启这个容器（docker restart 容器名）'
    return '没找到 ' + PROXY_NAMES[kind] + ' 的服务，请自己重启一下代理（或者重启 VPS）'


def enable_log(assume_yes=False):
    """给没有访问日志的 Xray / V2Ray / sing-box 打开访问日志：先备份配置，改完自检，再重启代理。"""
    if os.geteuid() != 0:
        raise RuntimeError('请使用 root 运行：liuliang --enable-log')
    procs = proxy_processes()
    if not procs:
        print('没找到正在运行的 Xray / V2Ray / sing-box。代理装好并运行后再试。')
        return
    todo = []
    for pid, kind, argv in procs:
        source, note, files, cwd, _log = proxy_log(pid, kind, argv)
        name = PROXY_NAMES[kind]
        if source and has_access_lines(source, kind):
            print('✔ ' + name + ' 的访问日志已经能读到（' + source[1] + '），不用改。')
            continue
        if panel_name(pid, argv):
            print('✘ ' + note)
            continue
        if not files:
            print('✘ 找不到 ' + name + ' 的配置文件，没法自动打开。请自己改：' + SITE_MANUAL)
            continue
        target = next((f for f in files if isinstance((load_json(f) or {}).get('log'), dict)), files[0])
        if load_json(target) is None:
            print('✘ ' + name + ' 的配置文件 ' + str(target) + ' 不是 JSON 格式，没法自动改。请自己改：' + SITE_MANUAL)
            continue
        todo.append((pid, kind, argv, cwd, Path(target)))
    if not todo:
        return
    for _pid, kind, _argv, _cwd, target in todo:
        print('将修改 ' + PROXY_NAMES[kind] + ' 的配置 ' + str(target) + '：打开访问日志，写到 ' + str(ACCESS_LOG) + '（会先备份原配置）')
    print('改完要重启一下代理：正在使用的人会断开几秒钟，然后自动重连。')
    if not assume_yes and has_tty():
        answer = ask('确定要继续吗？输入 y 回车继续：').lower()
        if answer not in ('y', 'yes'):
            print('已取消，什么都没改。')
            return
    for pid, kind, argv, cwd, target in todo:
        name = PROXY_NAMES[kind]
        uid = int((proc_status(pid).get('Uid', '0').split() or ['0'])[0])
        ACCESS_DIR.mkdir(parents=True, exist_ok=True)
        ACCESS_LOG.touch()
        for path in (ACCESS_DIR, ACCESS_LOG):
            os.chown(str(path), uid, -1)
        ACCESS_DIR.chmod(0o700)
        ACCESS_LOG.chmod(0o600)
        original = target.read_bytes()
        st = target.stat()
        backup = target.with_name(target.name + '.liuliang-bak-' + time.strftime('%Y%m%d%H%M%S'))
        backup.write_bytes(original)
        data = load_json(target)
        log = data.get('log') if isinstance(data.get('log'), dict) else {}
        if kind == 'sing-box':
            log.pop('disabled', None)
            if str(log.get('level') or 'info').lower() in ('warn', 'warning', 'error', 'fatal', 'panic'):
                log['level'] = 'info'
            log['output'] = str(ACCESS_LOG)
            log.setdefault('timestamp', True)
        else:
            log['access'] = str(ACCESS_LOG)
        data['log'] = log
        target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
        os.chmod(str(target), st.st_mode & 0o7777)
        try:
            os.chown(str(target), st.st_uid, st.st_gid)
        except OSError:
            pass
        try:
            exe = os.readlink('/proc/%s/exe' % pid)
        except OSError:
            exe = argv[0]
        exe = exe[:-len(' (deleted)')] if exe.endswith(' (deleted)') else exe   # 代理升级过、还没重启
        ok, detail = check_config(kind, exe, argv, cwd)
        if not ok:
            target.write_bytes(original)
            backup.unlink()
            print('✘ ' + name + ' 检查新配置没通过，已还原原配置，什么都没改' + ('（' + detail + '）' if detail else ''))
            continue
        try:
            todo_msg = restart_proxy(pid, kind, target)
        except (OSError, subprocess.CalledProcessError) as exc:
            target.write_bytes(original)
            backup.unlink()
            try:
                restart_proxy(pid, kind, target)
            except (OSError, subprocess.CalledProcessError):
                pass
            print('✘ ' + name + ' 重启失败，已还原原配置：' + str(getattr(exc, 'stderr', '') or exc).strip())
            continue
        print('✔ ' + name + ' 访问日志已打开（原配置备份在 ' + str(backup) + '）')
        if todo_msg:
            print('  还差一步：' + todo_msg)
    # liuliang 后台立刻重新找日志，不用等 5 分钟。
    if systemd_running():
        subprocess.run(['systemctl', 'restart', 'liuliang'], capture_output=True)
    elif shutil.which('rc-service'):
        subprocess.run(['rc-service', 'liuliang', 'restart'], capture_output=True)
    print('完成。之后的访问会开始记录：过几分钟运行 liuliang，输入序号查看。')


class FileFollower:
    """像 tail -F 一样跟着读日志文件，日志轮转（换文件 / 清空）后从新文件开头读。"""

    def __init__(self, path):
        self.path = path
        self.cap = access_cap()  # 日志超过这个大小就清空
        self.handle = None
        self.ident = None
        self.buf = ''
        self._open(seek_end=True)

    def _open(self, seek_end):
        try:
            handle = open(self.path, 'r', errors='replace')
        except OSError:
            return
        st = os.fstat(handle.fileno())
        if seek_end:
            handle.seek(0, 2)
        self.handle, self.ident, self.buf = handle, (st.st_dev, st.st_ino), ''

    def _read(self):
        if self.handle is None:
            return []
        data = self.handle.read(256 << 10)  # 每次最多读 256KB，小内存机器不爆
        if not data:
            return []
        lines = (self.buf + data).split('\n')
        self.buf = lines.pop()
        if len(self.buf) > 65536:
            self.buf = ''
        return lines

    def lines(self):
        if self.handle is None:
            self._open(seek_end=False)
            return self._read()
        out = self._read()
        # --enable-log 打开的日志由 liuliang 负责清理：读完、超过 20MB 就清空（代理是追加写，不受影响）。
        if self.path == str(ACCESS_LOG) and self.handle.tell() > self.cap and not self.buf:
            try:
                os.truncate(self.path, 0)
                self.handle.seek(0)
            except OSError:
                pass
        try:
            st = os.stat(self.path)
        except OSError:
            return out
        if (st.st_dev, st.st_ino) != self.ident or st.st_size < self.handle.tell():
            self.handle.close()
            self.handle = None
            self._open(seek_end=False)
            out += self._read()
        return out

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None


class JournalFollower:
    """journalctl -f 跟着读代理服务输出到 systemd 日志里的访问记录。"""

    def __init__(self, units):
        self.units = list(units)
        self.lock = threading.Lock()
        self.buf = []
        self.proc = None
        self.alive = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        cmd = ['journalctl', '-f', '-n', '0', '-q', '-o', 'cat'] + [x for u in self.units for x in ('-u', u)]
        while self.alive:
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='replace')
                for line in self.proc.stdout:
                    with self.lock:
                        if len(self.buf) < 100000:
                            self.buf.append(line.rstrip('\n'))
                self.proc.wait()
            except OSError:
                pass
            if self.alive:
                time.sleep(10)

    def lines(self):
        with self.lock:
            data, self.buf = self.buf, []
            return data

    def close(self):
        self.alive = False
        if self.proc is not None:
            self.proc.kill()


def peer_port(key):
    """ss 流的 key：tcp|本机|端口|对端|端口，取对端（客户端）端口。"""
    try:
        return int(str(key).split('|')[4])
    except (IndexError, ValueError):
        return None


class SiteTracker:
    """后台跟着读访问日志，每 2 秒看一次 ss，把每条连接的字节记到它访问的域名上。"""

    def __init__(self, ports, extra=()):
        self.ports = set(ports)
        self.extra = list(extra)
        self.lock = threading.Lock()
        self.parser = AccessParser()
        self.followers = {}
        self.journal = None
        self.watcher = None
        self.conns = {}    # (ip, 客户端端口) -> [域名, 认到的时间, ss 里还在]；域名 None = 多个网站共用（mux）
        self.base = {}     # 流 key -> [已记字节, 时间]
        self.closed = {}   # 已关闭、日志还没对上的流：key -> (ip, up, down, 关闭时间)
        self.usage = {}    # (ip, 域名) -> [字节, 次数, 最近一次打开的时间]
        self.status = None  # 还没找过日志时不写状态，免得报表误说「读不到」

    def start(self):
        self.watcher = ClosedWatcher(self.ports)
        if not self.watcher.start():
            self.watcher = None
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def set_ports(self, ports):
        self.ports = set(ports)
        if self.watcher is not None:
            self.watcher.ports = set(ports)

    def refresh(self):
        sources, notes = site_sources(self.extra)
        files = [p for kind, p in sources if kind == 'file']
        units = sorted(u for kind, u in sources if kind == 'journal')
        for path in list(self.followers):
            if path not in files:
                self.followers.pop(path).close()
        for path in files:
            if path not in self.followers:
                self.followers[path] = FileFollower(path)
        if (self.journal.units if self.journal else []) != units:
            if self.journal is not None:
                self.journal.close()
            self.journal = JournalFollower(units) if units else None
        with self.lock:
            self.status = {'sources': [kind + ':' + p for kind, p in sources], 'notes': notes}

    def _run(self):
        scanned = 0
        while True:
            try:
                now = time.time()
                if now - scanned >= SITE_RESCAN:
                    scanned = now
                    self.refresh()
                lines = []
                for follower in self.followers.values():
                    lines += follower.lines()
                if self.journal is not None:
                    lines += self.journal.lines()
                self.tick(now, lines)
            except Exception as exc:
                print('liuliang: 网站记录 ' + str(exc), file=sys.stderr, flush=True)
            time.sleep(POLL)

    def tick(self, now, lines, flows=None, closed=None):
        with self.lock:
            for line in lines:
                event = self.parser.feed(line)
                if event:
                    self._map(now, *event)
            if closed is None:
                closed = self.watcher.drain() if self.watcher is not None else {}
            for key, (ip, up, down) in closed.items():
                self.closed[key] = (ip, up, down, now)
            if not self.conns:
                for k in [k for k, v in self.closed.items() if now - v[3] > SITE_GRACE]:
                    del self.closed[k]
                return
            if flows is None:
                flows = parse_ss(read_ss() or '', self.ports)
            for entry in self.conns.values():
                entry[2] = False
            for key, (ip, up, down) in flows.items():
                entry = self.conns.get((ip, peer_port(key)))
                if entry is not None:
                    entry[2] = True
                    self._account(key, ip, entry, up + down, now)
            for key, (ip, up, down, t) in list(self.closed.items()):
                entry = self.conns.get((ip, peer_port(key)))
                if entry is not None:
                    self._account(key, ip, entry, up + down, now)
                    entry[2] = False
                    del self.closed[key]
                    self.base.pop(key, None)
                elif now - t > SITE_GRACE:
                    del self.closed[key]
            for k in [k for k, e in self.conns.items() if not e[2] and now - e[1] > SITE_KEEP]:
                del self.conns[k]
            for k in [k for k, b in self.base.items() if now - b[1] > FLOW_KEEP]:
                del self.base[k]

    def _map(self, now, ip, port, host):
        use = self.usage.setdefault((ip, host), [0, 0, now])
        use[1] += 1
        use[2] = now
        old = self.conns.get((ip, port))
        # 同一条连接还开着（或刚认到）又来了别的网站：mux，字节分不开。
        if old is not None and old[0] != host and (old[2] or now - old[1] < 5):
            old[0], old[1] = None, now
        else:
            self.conns[(ip, port)] = [host, now, False]

    def _account(self, key, ip, entry, total, now):
        old = self.base.get(key)
        before = old[0] if old else 0
        delta = total - before if total >= before else total
        self.base[key] = [total, now]
        if entry[0] and delta > 0:
            # 只加流量，不改最近访问时间：那个时间只在打开网站/App（日志里新的一次访问）时更新。
            use = self.usage.setdefault((ip, entry[0]), [0, 0, 0])
            use[0] += delta

    def drain(self):
        with self.lock:
            data, self.usage = self.usage, {}
            return data, (dict(self.status) if self.status is not None else None)


def start_sites(config):
    if not config.get('sites', True):
        return None
    tracker = SiteTracker(config['ports'], config.get('access_logs') or [])
    try:
        tracker.start()
    except Exception as exc:
        print('liuliang: 网站记录没能启动：' + str(exc), file=sys.stderr, flush=True)
        return None
    return tracker


def save_sites(c, tracker, now):
    """把这一轮每个 IP 访问的域名、字节、次数写进 sites 表，只留 8 天。"""
    if tracker is None:
        return
    data, status = tracker.drain()
    rows = [(now, ip, host, int(b), int(h), last) for (ip, host), (b, h, last) in data.items() if b > 0 or h > 0]
    if rows:
        c.executemany('INSERT INTO sites(ts,ip,host,bytes,hits,last) VALUES(?,?,?,?,?,?)', rows)
    if status is not None:
        c.execute("INSERT OR REPLACE INTO metadata VALUES('sites',?)", (json.dumps(dict(status, at=now), ensure_ascii=False),))
    c.execute('DELETE FROM sites WHERE ts<?', (now - 8 * 86400,))


def apply_nft(text):
    """写入规则文件。内容和正在用的表一致时不动内核计数器，变了才换表（返回 True）。"""
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.nft') as handle:
        handle.write(text)
        handle.flush()
        run(['nft', '-c', '-f', handle.name], capture_output=True)
    path = CONFIG.parent / 'counters.nft'
    previous = path.read_text() if path.exists() else None
    path.write_text(text)
    if previous == text and table_loaded():
        return False
    if table_loaded():
        run(['nft', 'delete', 'table', 'inet', TABLE])
    run(['nft', '-f', str(path)], capture_output=True)
    return True


def clear_counters():
    """换了新表，内核计数从 0 开始：旧基线作废，否则新计数会被少算。旧表的数已经先落盘。"""
    c = open_db()
    try:
        c.execute('DELETE FROM counters')
        c.commit()
    finally:
        c.close()


def install(args):
    if os.geteuid() != 0:
        raise RuntimeError('请使用 root 用户运行安装')
    if Path('/run/systemd/system').is_dir():
        init = 'systemd'
    elif Path('/sbin/openrc-run').exists():
        init = 'openrc'
    else:
        raise RuntimeError('需要正在使用 systemd 或 OpenRC 的 Linux VPS')
    existing = saved_config()
    detected, mode = [], None
    service = scan_ports(True)[2]
    if not args.ports:
        # 全自动：代理端口（TCP+UDP，hy2 的纯 UDP 端口也能认出来）+ 其他对外
        # 服务的 TCP 端口（比如文件传输网站）。UDP 临时端口不算；代理若只绑在
        # 回环上，改统计前面的对外端口。都没有时再用本机对外监听端口（不含 SSH 22）。
        # 更新时也会重新检测，新端口自动并入（已有端口保留）。
        detected, mode = detect_ports(proxy_only=True)
        if not detected:
            detected, mode = detect_ports(proxy_only=False)
            mode = 'fallback' if detected else None
        if len(detected) > 64:
            print('监听端口超过 64 个，只统计其中 64 个。需要取舍时用 --ports 指定。')
            detected = detected[:64]
    selected, geo, updating = resolve_install(existing, args, detected)
    listed = ','.join(map(str, selected))
    # 网站端口（文件分享网盘等非代理服务）：访客门槛更低，表格里标「网站」。
    web = sorted((set(service) | set((existing or {}).get('web') or [])) & set(selected))
    # 先探测、再停服务。nft 没权限时改走连接采样，两种都不行才退出。
    nft_text = rules(selected, web)
    backend, sources, nft_detail = probe_backend(nft_text)
    if backend == 'diag':
        explain_diag(nft_detail, sources)
    if updating and not args.ports:
        added = sorted(set(selected) - set(existing['ports']))
        if added:
            print('已安装 liuliang，更新到 ' + VERSION + '。新增检测到端口 ' + ','.join(map(str, added)) + '，已并入统计（原有端口保留）。已有流量保留。')
        else:
            print('已安装 liuliang，更新到 ' + VERSION + '。保留端口 ' + listed + ' 和已有流量。')
    elif updating:
        print('已安装 liuliang，更新到 ' + VERSION + '。端口改为 ' + listed + '。已有流量保留。')
    elif args.ports:
        print('使用手动指定的端口：' + listed)
    elif mode == 'proxy':
        print('自动检测到端口：' + listed + '（代理端口 + 其他对外服务端口；NAT VPS 取内部监听端口）')
    elif mode == 'frontend':
        print('代理只监听在回环地址，已改统计对外端口：' + listed + '（常见于前面还有 nginx/caddy）')
    elif mode == 'loopback':
        print('只检测到回环地址上的代理端口：' + listed)
    elif mode == 'service':
        print('未识别出代理进程，已自动选用本机对外服务端口：' + listed + '（不含 SSH 22）')
    else:
        print('未识别出代理进程，已自动选用本机对外监听端口：' + listed + '（不含 SSH 22）')
    if web:
        print('网站端口：' + ','.join(map(str, web)) + '（文件分享等网站，上传/下载达到 ' + sz(WEB_MIN_BYTES) + ' 就显示访客 IP）')
    if cloudflared_running():
        print('检测到 Cloudflare Tunnel（cloudflared）：网站访客不经过公网端口，改从本机转发的请求头认真实 IP。')
    if not updating or args.geo is not None:
        if geo:
            print('城市查询：已开启（向 ipwho.is 发送客户端 IP；归属地是估计值，仅供参考）')
        else:
            print('城市查询：已关闭')
    # 先停采集，再把内核里还没落盘的计数记下来。更新不删除 /var/lib/liuliang。
    stop_service(init)
    if updating and table_loaded():
        try:
            collect({'ports': selected, 'geo': False})
        except Exception as exc:
            print('更新前没能记下最后一次采样，继续更新：' + str(exc), file=sys.stderr)
    # auto：以后新装的网站/节点端口由后台自动并入；手动 --ports 的不自动加。
    auto = not args.ports if not updating or args.ports else bool(existing.get('auto', True))
    # realip：网站在 Cloudflare 后面时，从本机反代转发的请求头里认真实访客 IP。
    if getattr(args, 'realip', None) is not None:
        realip = args.realip != 'no'
    else:
        realip = bool((existing or {}).get('realip', True))
    # sites：读代理访问日志，记下每个 IP 访问了哪些应用/网站、各用了多少流量。
    if getattr(args, 'sites', None) is not None:
        sites = args.sites != 'no'
    else:
        sites = bool((existing or {}).get('sites', True))
    if getattr(args, 'access_log', None):
        access_logs = [p.strip() for p in args.access_log.split(',') if p.strip()]
    else:
        access_logs = list((existing or {}).get('access_logs') or [])
    # log：安装时是否自动打开代理访问日志（yes/no），用户明确选过就一直保留。
    explicit_log = getattr(args, 'log', None) in ('yes', 'no') or (existing or {}).get('log') in ('yes', 'no')
    log_choice = auto_log_choice(getattr(args, 'log', None), existing, mem_mb())
    config = {'version':VERSION, 'ports':selected, 'geo':geo, 'backend':backend, 'web':web, 'auto':auto, 'realip':realip,
              'sites':sites, 'access_logs':access_logs}
    if explicit_log:
        config['log'] = log_choice
    # billing：服务商计费方式。已经选过就一直保留（更新不再问），没选过默认进+出。
    config['billing'] = (existing or {}).get('billing') or ''
    # reset_day：每月几号重置流量。选过就保留，没选过安装时问一次。
    config['reset_day'] = (existing or {}).get('reset_day') or 0
    if backend == 'diag':
        config['diag'] = sources
    for folder in [CONFIG.parent, PROGRAM.parent, DATA]:
        folder.mkdir(parents=True, exist_ok=True)
    DATA.chmod(0o700)
    CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2)+'\n')
    CONFIG.chmod(0o600)
    if backend == 'nft' and apply_nft(nft_text):
        clear_counters()
    PROGRAM.write_bytes(Path(__file__).read_bytes()); PROGRAM.chmod(0o755)
    wrapper = Path('/usr/local/bin/liuliang')
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/liuliang/liuliang.py "$@"\n'); wrapper.chmod(0o755)
    if init == 'systemd':
        Path('/etc/systemd/system/liuliang.service').write_text('''[Unit]
Description=Per-IP port traffic statistics
After=network.target nftables.service
[Service]
Type=simple
Environment=MALLOC_ARENA_MAX=1 PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -u /usr/local/lib/liuliang/liuliang.py --daemon
Restart=on-failure
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
''')
        run(['systemctl','daemon-reload'])
        run(['systemctl','enable','liuliang'])
        run(['systemctl','restart','liuliang'])
        run(['systemctl','is-active','--quiet','liuliang'])
    else:
        logdir = Path('/var/log/liuliang'); logdir.mkdir(exist_ok=True); logdir.chmod(0o700)
        service = Path('/etc/init.d/liuliang')
        service.write_text('''#!/sbin/openrc-run
name="liuliang"
description="Per-IP port traffic statistics"
supervisor="supervise-daemon"
command="/usr/bin/python3"
export MALLOC_ARENA_MAX=1
command_args="-u /usr/local/lib/liuliang/liuliang.py --daemon"
respawn_delay=5
respawn_max=5
respawn_period=60
output_log="/var/log/liuliang/collector.log"
error_log="/var/log/liuliang/collector.log"
depend() { need net; after firewall nftables; }
start_pre() { /usr/bin/python3 /usr/local/lib/liuliang/liuliang.py --once; }
'''); service.chmod(0o755)
        run(['rc-service','liuliang','restart'])
        run(['rc-update','add','liuliang','default'])
        run(['rc-service','liuliang','status'])
    collect(config)
    done = '更新完成' if updating else '安装完成'
    how = 'nftables' if backend == 'nft' else '连接采样'
    print('\n'+done+'。以后输入：liuliang\n端口：'+','.join(map(str,selected))+'；城市查询：'+('已启用' if geo else '关闭')+'；统计：'+how
          +'；Cloudflare 后的真实访客 IP：'+('已开启' if config['realip'] else '关闭'))
    if sites:
        sources, notes = site_sources(access_logs)
        print('访问的应用/网站：已开启（读代理访问日志，只记域名和流量，不记网址和内容；--sites no 关闭）')
        for note in notes:
            print('  原因：' + note)
        if can_enable(sources, notes) and proxy_processes():
            print('  现在还读不到代理的访问记录，所以看不到每个 IP 访问了哪些网站。')
            # 默认打开（推荐）：直接回车 = 打开；输入 n = 不打开，并记住这个选择，以后更新不再问。
            # 之前选过「打开」（config 里 log=yes），代理的日志设置后来被删了：直接重新加上，不再问。
            answer = 'y' if log_choice == 'yes' else 'n'
            if log_action(explicit_log, log_choice) == 'ask':
                tip = '（推荐，直接回车）' if log_choice == 'yes' else '（这台内存小，推荐不开，直接回车跳过）'
                got = ask('  要自动打开代理访问日志吗？会先备份代理配置、代理重启几秒' + tip + ' [y/n]：').lower()
                if got in ('y', 'yes', 'n', 'no'):
                    answer = got[0]
                    config['log'] = 'yes' if answer == 'y' else 'no'
                    CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2)+'\n')
            if answer == 'y':
                enable_log(assume_yes=True)
            else:
                print('  ' + SITE_HELP)
    if not config.get('billing'):
        config['billing'] = ask_billing('both')
        CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2)+'\n')
    if not config.get('reset_day'):
        config['reset_day'] = ask_reset_day(1)
        CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2)+'\n')
    print('计费方式：' + BILLING.get(config['billing'], '不确定（三种都显示）') + '；每月 %d 号重置' % config['reset_day'] + '（以后改：liuliang --billing / liuliang --reset-day 几号）')
    print('只看网站访客：liuliang --web    排查问题：liuliang --doctor')
    print('查看某个 IP 近7天访问的应用/网站：运行 liuliang 后输入序号，或 liuliang --ip IP')


def cloudflared_running():
    for comm in Path('/proc').glob('[0-9]*/comm'):
        try:
            if comm.read_text().strip().startswith('cloudflared'):
                return True
        except OSError:
            continue
    return False


def service_state():
    if Path('/run/systemd/system').is_dir():
        cmd = ['systemctl', 'is-active', 'liuliang']
    else:
        cmd = ['rc-service', 'liuliang', 'status']
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
    except OSError:
        return '未知'
    text = (out.stdout or out.stderr).strip().splitlines()
    return (text[-1] if text else '') + ('' if out.returncode == 0 else '（没在运行）')


def doctor():
    """把“为什么看不到网站访客 IP”最常见的几种原因逐条查一遍。"""
    ok = lambda b: col('✔', G) if b else col('✘', Y)
    print(col('liuliang ' + VERSION + ' 自检', B, C))
    config = saved_config()
    if not config:
        print(ok(False) + ' 没有安装（/etc/liuliang/config.json 不存在），先运行一键安装'); return
    print(ok(True) + ' 统计方式：' + ('nftables' if config.get('backend') != 'diag' else '连接采样 ' + json.dumps(config.get('diag') or {})))
    state = service_state()
    print(ok('没在运行' not in state) + ' 后台服务：' + state)
    print('  统计端口：' + ','.join(map(str, config['ports'])))
    print('  网站端口：' + (','.join(map(str, config.get('web') or [])) or '无'))
    try:
        backends = backend_ports()
    except Exception:
        backends = []
    listening = set()
    try:
        listening = {i['port'] for i in iter_sockets(read_socket_table()) if i['proto'] == 'tcp'}
    except Exception:
        pass
    missing = sorted(p for p in listening - set(config['ports']) - {22} if p in backends and p not in (config.get('web') or []))
    if missing:
        print('  本机还有这些 TCP 端口在监听但没统计：' + ','.join(map(str, missing)) + '（只绑 127.0.0.1 的是正常的，由反代转过去）')
    tunnel = cloudflared_running()
    realip = config.get('realip', True)
    print(ok(realip) + ' Cloudflare 后的真实访客 IP 识别：' + ('开启' if realip else '关闭（重装时加 --realip yes 打开）'))
    print('  回环口要看的网站后端端口：' + (','.join(map(str, backends)) or '无'))
    if tunnel:
        print('  检测到 cloudflared（Cloudflare Tunnel）：访客 IP 只能从请求头取，需要上面这项开启')
    sites = config.get('sites', True)
    print(ok(sites) + ' 访问的应用/网站记录：' + ('开启' if sites else '关闭（重装时加 --sites yes 打开）'))
    if sites:
        sources, notes = site_sources(config.get('access_logs') or [])
        names = [('日志文件 ' if kind == 'file' else 'systemd 日志 ') + p for kind, p in sources]
        print(ok(bool(sources)) + ' 代理访问日志：' + ('、'.join(names) or '没找到'))
        for note in notes:
            print('  原因：' + note)
        if can_enable(sources, notes):
            print('  ' + SITE_HELP)
    db = DATA / 'history-v1.db'
    if not db.exists():
        print(ok(False) + ' 还没有流量数据库：服务刚装好的话等两分钟'); return
    c = sqlite3.connect(str(db), timeout=30)
    try:
        meta = dict(c.execute('SELECT key,value FROM metadata'))
        now = time.time()
        sample = float(meta.get('sample') or 0)
        if sample:
            print(ok(now - sample < 600) + ' 最近一次落盘：%d 秒前' % (now - sample))
        ips = [ip for ip, in c.execute('SELECT ip FROM clients WHERE last_seen>=?', (now - 604800,))]
        cf = [ip for ip in ips if is_cloudflare(ip)]
        print('  近7天记录到 IP %d 个，其中 Cloudflare 节点 %d 个' % (len(ips), len(cf)))
        last = float(meta.get('realip_last') or 0)
        if last:
            print(ok(True) + ' 最近一次从请求头认出真实访客：' + datetime.fromtimestamp(last, Z).strftime('%Y-%m-%d %H:%M:%S'))
        elif cf or tunnel:
            print(ok(False) + ' 还没从请求头认出过真实访客。用浏览器打开一次网站、等两分钟再看；'
                  '仍然没有的话，确认网站程序是本机反代（Caddy/nginx/cloudflared）用 http 转过去的')
        if cf and not last:
            print('  说明：网站开了 Cloudflare 代理（橙色云），公网端口上只能看到 Cloudflare 的 IP。')
    finally:
        c.close()


def main():
    parser = argparse.ArgumentParser(description='按 IP 查看近24小时和近7天端口流量')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--ports', help='高级：手动指定统计端口，如 443,8443（默认自动检测）')
    parser.add_argument('--geo', choices=['yes','no'], help='高级：--geo no 关闭城市查询（默认开启）')
    parser.add_argument('--realip', choices=['yes','no'], help='高级：--realip no 关闭 Cloudflare 后真实访客 IP 识别（默认开启）')
    parser.add_argument('--wide', action='store_true', help='宽表：多显示运营商、近24小时等栏（电脑上看）')
    parser.add_argument('--web', action='store_true', help='只看网站访客（有网站流量就显示，不设门槛）')
    parser.add_argument('--all', action='store_true', help='显示全部 IP：包括未达门槛的和 Cloudflare 节点 IP')
    parser.add_argument('--doctor', action='store_true', help='检查安装状态，排查“看不到访客 IP”')
    parser.add_argument('--ip', help='查看这个 IP 近7天访问的应用/网站和各自的流量')
    parser.add_argument('--sites', choices=['yes','no'], help='高级：--sites no 关闭访问的应用/网站记录（默认开启）')
    parser.add_argument('--access-log', help='高级：代理访问日志路径（自动找不到时用），多个用逗号隔开')
    parser.add_argument('--billing', nargs='?', const='', choices=['', 'both', 'out', 'max', 'all'], help='设置服务商计费方式：both 进+出 / out 出站 / max 取大 / all 三种都显示')
    parser.add_argument('--reset-day', nargs='?', const='', help='设置服务商每月几号重置流量（1-31），不带数字就一步一步问')
    parser.add_argument('--log', choices=['yes','no'], help='高级：安装时是否自动打开代理访问日志（默认打开，内存<48MB 默认不开）')
    parser.add_argument('--enable-log', action='store_true', help='自动打开 Xray / sing-box 的访问日志（看不到访问的网站时用）')
    parser.add_argument('-y', '--yes', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--daemon', action='store_true')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    if args.install:
        install(args); return
    if args.doctor:
        doctor(); return
    if args.enable_log:
        enable_log(args.yes); return
    if args.billing is not None:
        set_billing(args.billing or None)
        # 不带参数的 --billing 顺便问一下重置日（直接回车保留原值）。
        if not args.billing:
            set_reset_day(None)
        return
    if args.reset_day is not None:
        set_reset_day(args.reset_day or None); return
    config = json.loads(CONFIG.read_text())
    if args.once:
        collect(config)
    elif args.daemon:
        if config.get('backend') == 'diag':
            diag_daemon(config)
            return
        seen = set()
        sniffer = start_sniffer(config)
        sites = start_sites(config)
        while True:
            try:
                collect(config, sniffer, sites)
            except Exception as exc:
                print('liuliang:', str(exc), file=sys.stderr, flush=True)
            # 两分钟采一次，端口每分钟看一次：新端口最多约 2 分钟后开始统计。
            for _ in range(INTERVAL // RESCAN):
                try:
                    refresh_sniffer(sniffer)
                    seen, changed = follow_ports(config, seen)
                    if changed:
                        reload_nft(config)
                        if sites is not None:
                            sites.set_ports(config['ports'])
                except Exception as exc:
                    print('liuliang:', str(exc), file=sys.stderr, flush=True)
                time.sleep(RESCAN)
    elif args.ip:
        site_report(args.ip, config, show_all=args.all)
    else:
        report(config, web_only=args.web, show_all=args.all, wide=args.wide)


from datetime import datetime,timedelta,timezone
Z=timezone(timedelta(hours=8)); E='\33[0m'; B='\33[1m'; C='\33[36m'; G='\33[32m'; Y='\33[33m'; D='\33[2m'; X='\33[90m'
def col(x,*a): return ''.join(a)+str(x)+E if sys.stdout.isatty() and a else str(x)
def sz(n):
 u=['B','KB','MB','GB','TB'];v=float(max(0,n or 0))
 for q in u:
  if v<1024 or q==u[-1]: break
  v/=1024
 return f'{v:.0f} {q}' if q=='B' or v>=10 else f'{v:.1f} {q}'
def ww(s): return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WFA' else 1 for c in str(s))
def cell(s,n): return str(s)+' '*(n-ww(s))
def diff(c,ip,a,b,col='bytes'):
 return c.execute(f'select coalesce(sum({col}),0) from traffic where ip=? and ts>? and ts<=?',(ip,a,b)).fetchone()[0]
def report(config, web_only=False, show_all=False, wide=True):
 DB=str(DATA / "history-v1.db")
 now=time.time();print(col('端口 '+','.join(map(str,config['ports']))+' · 近7天'+('网站访客' if web_only else '连接'),B,C))
 if not os.path.exists(DB):
  if DATA.exists() and not os.access(str(DATA), os.R_OK | os.X_OK):
   print('无法读取流量数据，请使用 root 运行：liuliang');return
  print('(暂无流量数据库记录)');return
 # 显示门槛：默认 0（全显示），config.json 里 min_kb 可调。
 limit=int(config.get('min_kb',MIN_TRAFFIC_BYTES//1024) or 0)*1024
 c=sqlite3.connect(DB, timeout=30); rows=[]; cfhidden=0; picks=[]
 try:
  hasweb='web' in [r[1] for r in c.execute('PRAGMA table_info(traffic)')]
  cols=[r[1] for r in c.execute('PRAGMA table_info(clients)')]
  sel='ip,country,city,isp,last_seen' if 'isp' in cols else 'ip,country,city,last_seen'
  # 最后上网 = 这个 IP 最后一次打开网站/App 的时间（代理访问日志里最后一次访问）。
  # 读不到访问日志的 IP 退回到最后一个数据包的时间，标 *（手机后台心跳也算，会偏晚）。
  hassites='sites' in {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
  opened=dict(c.execute('select ip,max(last) from sites where ts>? and hits>0 group by ip',(now-604800,))) if hassites and not web_only else {}
  for rec in c.execute(f'select {sel} from clients where last_seen>=? order by last_seen desc',(now-604800,)):
   ip,co,ci=rec[0],rec[1],rec[2]; isp,ls=(rec[3],rec[4]) if len(rec)==5 else ('',rec[3])
   d=diff(c,ip,now-86400,now);w=diff(c,ip,now-604800,now);wb=diff(c,ip,now-604800,now,'web') if hasweb else 0
   # Cloudflare 回源节点不是访客：真实访客已经从请求头单独记了，默认不显示。
   # 只认「几乎全是网站流量」的：用 WARP 连节点的人出口也在 Cloudflare 网段，照常显示。
   cf=is_cloudflare(ip) and wb>0 and w-wb<WEB_MIN_BYTES
   if cf and not show_all:
    if w>0: cfhidden+=1
    continue
   if web_only:
    if wb<=0: continue
    d=diff(c,ip,now-86400,now,'web') if hasweb else 0;w=wb
   # 节点流量 800KB 起显示；网站（文件分享）访客上传/下载 20KB 起就显示。
   # 节点流量（总流量减网站部分）大于 0 且达到门槛就显示；纯网站访客仍要 20KB 起，挡掉扫描器。
   # 设了 min_kb：只看表格里「7天」那一栏的数字（进+出合计，1KB=1024 字节），低于就藏，和显示的完全一致。
   elif not show_all and limit and w<limit: continue
   # 没设门槛：有节点流量就显示；纯网站访客仍要 20KB 起，挡掉扫描器。
   elif not show_all and not limit and not w-wb>0 and wb<WEB_MIN_BYTES: continue
   kind='CF节点' if cf else '+'.join(k for k,ok in (('节点',w-wb>=WEB_MIN_BYTES),('网站',wb>=WEB_MIN_BYTES or web_only and wb>0)) if ok) or ('网站' if wb>0 and wb>=w-wb else '节点')
   # 最后上网 = 最后打开网站时间 和 最后一个数据包时间 里更晚的那个：
   # 长连接（看视频、下载）一直有数据时，时间也会跟着走，不会停在刚连上那一刻。
   mark='' if web_only or opened.get(ip) else '*';ls=max(float(opened.get(ip) or 0),float(ls))
   age=max(0,now-float(ls));place=ci or co or ('Cloudflare' if cf else '未解析');rows.append((ip,isp_display(isp),place,d,w,ls,age,kind,mark))
  rows.sort(key=lambda r:-float(r[5]))
  # 疑似扫描 IP 不显示、不计入合计（规则见 scan_ips；liuliang --all 全显示）。
  scanhidden=0
  if not show_all and not web_only:
   bad=scan_ips(c,[r for r in rows if r[7]!='CF节点'],config,opened,now,hasweb)
   scanhidden=len(bad);rows=[r for r in rows if r[0] not in bad]
  note=('已隐藏 %d 个 Cloudflare 节点 IP（橙色云/Tunnel）\n真实访客已单独列出，查看：liuliang --all'%cfhidden) if cfhidden else ''
  if scanhidden:note=(note+'\n' if note else '')+'已隐藏 %d 个疑似扫描 IP，查看：liuliang --all'%scanhidden
  # NAT 小鸡：来访地址全是商家网关的内网地址，看不到真实用户。
  natips=[r[0] for r in rows if is_nat_ip(r[0])]
  if natips and len(natips)*2>=len(rows):
   note=(note+'\n' if note else '')+'这台是 NAT 小鸡，商家的网关把来访地址\n换成了 %s，看不到用户真实 IP，\n只能显示总流量'%'、'.join(natips[:2])
  if not rows:
   print('(近7天没有网站访客)' if web_only else ('(近7天无达到 %dKB 的流量记录'%(limit//1024) if limit else '(近7天没有流量记录')+('，也没有网站访客' if config.get('web') else '')+')')
   if note:print(col(note,D))
   # 没有任何 IP 记录时，说一下最可能的原因。
   if not web_only and not cfhidden and not scanhidden:
    for t in ('可能的原因：','  1. 还没人用过节点（用一下，2 分钟后再看）','  2. 节点端口没在统计里：liuliang --doctor','  3. 统计没在跑：liuliang --doctor 看后台服务'):print(col(t,D))
   # 网卡用量不依赖 IP 记录，有数据就照样显示。
   for t in billing_lines(config,c,now):print(col(t,D))
   if cfhidden and not c.execute("select 1 from metadata where key='realip_last'").fetchone():
    print('只看到 Cloudflare 的 IP、没有真实访客：运行 liuliang --doctor 排查')
   return
  showkind=web_only is False and any(r[7]!='节点' for r in rows)
  h=['#','IP','运营商','城市','24小时','7天','最后上网' if not web_only else '最近访问']+(['访问'] if showkind else []);N=[2,15,8,6,7,7,11]+([4] if showkind else [])
  vals=lambda n,ip,net,pl,d,w,ls,kind,mark:[n,ip,short(net),short(pl,10),sz(d),sz(w),datetime.fromtimestamp(ls,Z).strftime('%m-%d %H:%M')+mark]+([kind] if showkind else [])
  for n,r in enumerate(rows,1):N=[max(N[i],ww(x)) for i,x in enumerate(vals(n,*r[:6],r[7],r[8]))]
  if wide:
   def line(a,m,b):return a+m.join('─'*(n+2) for n in N)+b
   print(line('┌','┬','┐'));print(col('│ '+' │ '.join(cell(x,N[i]) for i,x in enumerate(h))+' │',B,C));print(line('├','┼','┤'))
   for n,(ip,net,pl,d,w,ls,age,kind,mark) in enumerate(rows,1):
    v=vals(n,ip,net,pl,d,w,ls,kind,mark);out=[]
    for i,x in enumerate(v):
     st=[D,X] if d<=0 and w<=0 or kind=='CF节点' else ([B,G] if i==1 and d>0 else [])
     if i==4 and d>=100*1024**2 or i==5 and w>=1024**3:st=[B,Y]
     if i==6:st=[B,G] if age<=3600 else ([D,X] if age>259200 else [])
     out.append(col(cell(x,N[i]),*st))
    print('│ '+' │ '.join(out)+' │')
   real=[r for r in rows if r[7]!='CF节点']
   print(line('└','┴','┘'));a=sum(1 for r in real if r[3]>0 or r[4]>0);print('合计：IP 数 %d · 有流量 IP 数 %d · 近24小时总流量 %s · 近7天总流量 %s'%(len(real),a,sz(sum(r[3] for r in real)),sz(sum(r[4] for r in real))))
  else:
   real=[r for r in rows if r[7]!='CF节点']
   # 窄表（默认）：只放 序号、IP、7天流量、最后上网、城市，约 45 格宽，手机竖屏也能一行看完。
   # 运营商、近24小时在 liuliang --wide 里看。
   K=[2,15,7,12,6];hc=['#','IP','7天','最后上网' if not web_only else '最近访问','城市']
   cv=lambda n,r:[str(n),r[0],sz(r[4]),datetime.fromtimestamp(r[5],Z).strftime('%m-%d %H:%M')+r[8],short(r[2],6)]
   for n,r in enumerate(rows,1):K=[max(K[i],ww(x)) for i,x in enumerate(cv(n,r))]
   print(col(' '.join(cell(x,K[i]) for i,x in enumerate(hc)).rstrip(),B,C))
   for n,r in enumerate(rows,1):
    st=[D,X] if r[4]<=0 or r[7]=='CF节点' else []
    print(col(' '.join(cell(x,K[i]) for i,x in enumerate(cv(n,r))).rstrip(),*st))
   print('合计 %d 个 IP · 24小时 %s · 7天 %s'%(len(real),sz(sum(r[3] for r in real)),sz(sum(r[4] for r in real))))
  # 服务商口径：整块网卡的进/出用量，按 config.json 里的 billing 显示。
  for t in billing_lines(config,c,now):print(col(t,D))
  if any(r[8] for r in rows) and not wide:print(col('带 * = 没有访问记录，按最后有数据的时间',D))
  if any(r[8] for r in rows) and wide:print(col('最后上网：这个 IP 最后一次打开网站/App 或最后有数据来往的时间（取更晚的，每分钟更新）。带 * 的读不到它打开网站的记录（代理没开日志，或是网站访客），'
   '手机放着不用、后台心跳也算数据，所以可能比实际晚',D))
  if note:print(col(note,D))
  picks=[r[0] for r in rows]
 finally:
  c.close()
 # 在终端里看表时，可以接着选一个 IP 看它访问了哪些应用/网站。
 if picks and sys.stdin.isatty() and sys.stdout.isatty():choose_ip(config,picks,show_all)


def choose_ip(config, picks, show_all=False):
    while True:
        try:
            text = input('\n输入序号或 IP，查看它近7天访问的应用/网站（直接回车退出）：').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not text:
            return
        if text.isdigit() and 1 <= int(text) <= len(picks):
            ip = picks[int(text) - 1]
        else:
            ip = normalize_ip(text)
            if ip is None:
                print('没有这个序号，也不是有效的公网 IP')
                continue
        print()
        site_report(str(ip), config, show_all)


def site_report(ip, config=None, show_all=False):
    """一个 IP 近7天访问的应用/网站：按应用归类，显示流量、访问次数和最近访问时间。"""
    DB = str(DATA / 'history-v1.db')
    found = normalize_ip(ip)
    ip = str(found) if found is not None else str(ip).strip()
    now = time.time(); since = now - 604800
    if not os.path.exists(DB):
        print('无法读取流量数据，请使用 root 运行：liuliang' if DATA.exists() and not os.access(str(DATA), os.R_OK | os.X_OK) else '(暂无流量数据库记录)')
        return
    c = sqlite3.connect(DB, timeout=30)
    try:
        tables = {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
        rows = list(c.execute('select host,sum(bytes),sum(hits),max(last) from sites where ip=? and ts>? group by host', (ip, since))) if 'sites' in tables else []
        total = diff(c, ip, since, now)
        info = c.execute('select * from clients where ip=?', (ip,)).fetchone()
        info = dict(zip([d[0] for d in c.execute('select * from clients limit 0').description], info)) if info else {}
        status = c.execute("select value from metadata where key='sites'").fetchone()
    finally:
        c.close()
    place = ' '.join(x for x in (isp_display(info.get('isp')) if info.get('isp') else '', info.get('country'), info.get('city')) if x)
    print(col(ip + (' · ' + place if place else '') + ' · 近7天访问的应用/网站', B, C))
    groups = {}
    for host, b, h, last in rows:
        g = groups.setdefault(site_label(host), [0, 0, 0, []])
        g[0] += b or 0; g[1] += h or 0; g[2] = max(g[2], last or 0); g[3].append((b or 0, h or 0, host))
    if not groups:
        if config is not None and not config.get('sites', True):
            print('访问的应用/网站记录已关闭（重装时加 --sites yes 打开）')
            return
        try:
            status = json.loads(status[0]) if status else None
        except ValueError:
            status = None
        if status is None:
            print('还没有记录：后台更新到 ' + VERSION + ' 后，从新产生的连接开始记，等两分钟再看')
        elif not status.get('sources'):
            notes = status.get('notes') or []
            print('看不到这个 IP 访问了哪些网站：liuliang 要读代理（Xray/sing-box）自己的访问记录，现在读不到。')
            for note in notes:
                print('  原因：' + note)
            if can_enable([], notes):
                print('  ' + SITE_HELP)
        else:
            print('(近7天这个 IP 没有访问记录' + ('，总流量 ' + sz(total) if total else '') + ')')
        return
    items = sorted(groups.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))
    limit = len(items) if show_all else 30
    shown, rest = items[:limit], items[limit:]
    def hosts(lst):
        lst = sorted(lst, key=lambda x: (-x[0], -x[1], x[2]))
        top = lst[0][2] if len(lst[0][2]) <= 36 else lst[0][2][:33] + '...'
        return top + (' 等%d个' % len(lst) if len(lst) > 1 else '')
    table = [[str(n), name, hosts(g[3]), sz(g[0]) if g[0] else '-', str(g[1]), datetime.fromtimestamp(g[2], Z).strftime('%Y-%m-%d %H:%M:%S') if g[2] else '-']
             for n, (name, g) in enumerate(shown, 1)]
    counted = sum(g[0] for _name, g in items)
    if rest:
        table.append(['', '其余 %d 个' % len(rest), 'liuliang --ip ' + ip + ' --all', sz(sum(g[0] for _n, g in rest)), str(sum(g[1] for _n, g in rest)), ''])
    other = total - counted
    if other > 0:
        table.append(['', '其他（无法细分）', 'UDP/mux 连接、协议开销', sz(other), '', ''])
    h = ['#', '应用/网站', '域名', '流量', '次数', '最近访问']
    N = [max([ww(x) for x in [h[i]] + [r[i] for r in table]]) for i in range(len(h))]
    line = lambda a, m, b: a + m.join('─' * (n + 2) for n in N) + b
    print(line('┌', '┬', '┐')); print(col('│ ' + ' │ '.join(cell(x, N[i]) for i, x in enumerate(h)) + ' │', B, C)); print(line('├', '┼', '┤'))
    for r in table:
        out = []
        for i, x in enumerate(r):
            big = r[0] and groups[r[1]][0] >= 1024 ** 3
            st = [D, X] if not r[0] else ([B, G] if i == 1 else ([B, Y] if i == 3 and big else []))
            out.append(col(cell(x, N[i]), *st))
        print('│ ' + ' │ '.join(out) + ' │')
    print(line('└', '┴', '┘'))
    print('合计：应用/网站 %d 个 · 访问 %d 次 · 已按网站细分 %s · 该 IP 近7天总流量 %s' % (len(items), sum(g[1] for _n, g in items), sz(counted), sz(max(total, counted))))
    if other > 0 or any(not g[0] for _n, g in items):
        print(col('流量为「-」的网站走的是 UDP（hy2/tuic）或 mux 连接，只能记次数，流量算在「其他」里', D))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print('错误：'+str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        sys.exit(1)
LIULIANG_PYTHON
python3 "$jobdir/liuliang.py" --install "$@"
