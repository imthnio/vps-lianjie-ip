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
import urllib.parse
import urllib.request

VERSION = '1.0.13'
CONFIG = Path('/etc/liuliang/config.json')
DATA = Path('/var/lib/liuliang')
TABLE = 'liuliang_v1'
PROGRAM = Path('/usr/local/lib/liuliang/liuliang.py')
INTERVAL = 120
POLL = 2
LOCK = Path('/run/liuliang.lock')
# 某次 ss/conntrack 读空时，已断开的流还留这么久，避免基线丢失后把累计字节再加一遍。
FLOW_KEEP = 120
# nft set 元素超时秒数，必须与 rules() 里 `timeout 8d` 保持一致。
# 每次有包命中，内核会把该元素的 expires 重置为该值，因此可以用它
# 反推出"最后一个包"的时间（约 1 秒精度），而不用采样时刻代替。
SET_TIMEOUT = 8 * 86400
# 展示过滤阈值：近7天总流量低于该值的 IP 不在表格中显示（也不计入合计）。
# 用户要求：低于 800KB 的流量不用统计。
MIN_TRAFFIC_BYTES = 800 * 1024


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


def rules(selected):
    selected = ports(','.join(map(str, selected)))
    portset = '{ ' + ', '.join(map(str, selected)) + ' }'
    lines = ['table inet ' + TABLE + ' {']
    for direction in ('up', 'down'):
        for version in (4, 6):
            lines.append(f' set {direction}{version} {{ type ipv{version}_addr; flags dynamic,timeout; timeout 8d; size 16384; }}')
    for chain, direction, field, address in [('input','up','dport','saddr'), ('output','down','sport','daddr')]:
        lines.append(f' chain {chain} {{ type filter hook {chain} priority 11; policy accept;')
        for version, family in [(4, 'ip'), (6, 'ip6')]:
            for protocol in ('tcp', 'udp'):
                lines.append(f'  meta nfproto ipv{version} {protocol} {field} {portset} update @{direction}{version} {{ {family} {address} counter }}')
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


def acceptable_ip(value):
    """全局可路由地址才入库。回环、组播、链路本地、保留和运营商级 NAT 都丢掉。

    Python 3.9 的 IPv4Address.is_global 不排除组播，所以这里逐项判断。
    """
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
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
        if obj.get('name') in ('up4','down4','up6','down6'):
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
    ''')
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
    last_seen = {}
    for (name, ip), (n, expires) in current.items():
        old = previous.get((name, ip), 0)
        delta = n - old if n >= old else n
        if delta > 0:
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
        c.execute('INSERT INTO traffic VALUES(?,?,?)', (now, ip, n))
        # 取四个方向里最晚的那个包的时间；没有 expires 时回退到采样时刻；
        # max() 保证 last_seen 只增不减，避免时钟抖动造成时间倒退。
        c.execute('INSERT INTO clients(ip,last_seen) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET last_seen=max(clients.last_seen, excluded.last_seen)', (ip, last_seen.get(ip, now)))
    c.execute('DELETE FROM traffic WHERE ts<?', (now - 8*86400,))
    c.execute('DELETE FROM clients WHERE last_seen<?', (now - 8*86400,))
    c.commit()


def geo_lookup(ip):
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


def collect(config):
    if config.get('backend') == 'diag':
        diag_tick(config, True)
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
            c.execute("INSERT OR REPLACE INTO metadata VALUES('boot',?)", (boot,))
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
    """返回 (端口列表, 来源)。来源是 proxy / frontend / loopback / service / fallback / none。

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
    if proxy_only:
        if public:
            return sorted(public | service), 'proxy'
        if loopback:
            if service:
                return sorted(service), 'frontend'
            return sorted(loopback), 'loopback'
        if service:
            return sorted(service), 'service'
        return [], 'none'
    fallback = set()
    for item in sockets:
        if item['port'] == 22 or item['scope'] == 'loop':
            continue
        if item['proto'] == 'tcp' or not in_ephemeral(item['port'], bounds):
            fallback.add(item['port'])
    return sorted(fallback), ('fallback' if fallback else 'none')


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

    def __init__(self, ports, count_tcp, count_udp):
        self.ports = set(ports)
        self.count_tcp = count_tcp
        self.count_udp = count_udp
        self.lock = threading.Lock()
        self.pending = {}

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
                    with self.lock:
                        self.pending[ip] = self.pending.get(ip, 0) + n

    def drain(self):
        with self.lock:
            data = self.pending
            self.pending = {}
            return data


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


def add_pending(c, activity, now):
    for ip, n in activity.items():
        if n <= 0:
            continue
        c.execute(
            'INSERT INTO pending(ip,bytes,last_seen) VALUES(?,?,?) '
            'ON CONFLICT(ip) DO UPDATE SET bytes=pending.bytes+excluded.bytes, '
            'last_seen=max(pending.last_seen, excluded.last_seen)',
            (ip, int(n), now),
        )


def take_pending(c, now):
    rows = list(c.execute('SELECT ip,bytes,last_seen FROM pending WHERE bytes>0'))
    for ip, n, seen in rows:
        c.execute('INSERT INTO traffic VALUES(?,?,?)', (now, ip, int(n)))
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


def diag_tick(config, flush, pump=None):
    ports = config['ports']
    sources = config.get('diag') or {}
    now = time.time()
    with open(LOCK, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = read_flow_snapshot(ports, sources)
        c = open_db()
        try:
            prev = load_flows(c)
            baselines, activity = account_flows(prev, current, now)
            if pump is not None:
                for ip, n in pump.drain().items():
                    if n > 0:
                        activity[ip] = activity.get(ip, 0) + n
            # 从已经有流量记录的 nft 安装切过来时，套接字上的历史字节不要再加一遍。
            if not prev and c.execute('SELECT 1 FROM traffic LIMIT 1').fetchone():
                activity = {}
            save_flows(c, baselines)
            add_pending(c, activity, now)
            if flush:
                take_pending(c, now)
            c.commit()
        finally:
            c.close()


def diag_daemon(config):
    sources = config.get('diag') or {}
    pump = None
    if sources.get('tcp') == 'raw' or sources.get('udp') == 'raw':
        pump = PacketPump(config['ports'], sources.get('tcp') == 'raw', sources.get('udp') == 'raw')
        try:
            if not pump.start():
                print('liuliang: 抓包没有权限，原始计数未启动', file=sys.stderr, flush=True)
                pump = None
        except OSError as exc:
            print('liuliang: ' + str(exc), file=sys.stderr, flush=True)
            pump = None
    last = 0
    while True:
        try:
            now = time.time()
            flush = now - last >= INTERVAL
            diag_tick(config, flush, pump)
            if flush:
                last = now
                if config.get('geo', True):
                    geo_resolve()
        except Exception as exc:
            print('liuliang:', str(exc), file=sys.stderr, flush=True)
        time.sleep(POLL)


def apply_nft(text):
    """写入规则文件。内容和正在用的表一致时不动内核计数器，变了才换表。"""
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.nft') as handle:
        handle.write(text)
        handle.flush()
        run(['nft', '-c', '-f', handle.name], capture_output=True)
    path = CONFIG.parent / 'counters.nft'
    previous = path.read_text() if path.exists() else None
    path.write_text(text)
    if previous == text and table_loaded():
        return
    if table_loaded():
        run(['nft', 'delete', 'table', 'inet', TABLE])
    run(['nft', '-f', str(path)], capture_output=True)


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
    # 先探测、再停服务。nft 没权限时改走连接采样，两种都不行才退出。
    nft_text = rules(selected)
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
    config = {'version':VERSION, 'ports':selected, 'geo':geo, 'backend':backend}
    if backend == 'diag':
        config['diag'] = sources
    for folder in [CONFIG.parent, PROGRAM.parent, DATA]:
        folder.mkdir(parents=True, exist_ok=True)
    DATA.chmod(0o700)
    CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2)+'\n')
    CONFIG.chmod(0o600)
    if backend == 'nft':
        apply_nft(nft_text)
    PROGRAM.write_bytes(Path(__file__).read_bytes()); PROGRAM.chmod(0o755)
    wrapper = Path('/usr/local/bin/liuliang')
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/liuliang/liuliang.py "$@"\n'); wrapper.chmod(0o755)
    if init == 'systemd':
        Path('/etc/systemd/system/liuliang.service').write_text('''[Unit]
Description=Per-IP port traffic statistics
After=network.target nftables.service
[Service]
Type=simple
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
    print('\n'+done+'。以后输入：liuliang\n端口：'+','.join(map(str,selected))+'；城市查询：'+('已启用' if geo else '关闭')+'；统计：'+how)


def main():
    parser = argparse.ArgumentParser(description='按 IP 查看近24小时和近7天端口流量')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--ports', help='高级：手动指定统计端口，如 443,8443（默认自动检测）')
    parser.add_argument('--geo', choices=['yes','no'], help='高级：--geo no 关闭城市查询（默认开启）')
    parser.add_argument('--daemon', action='store_true')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    if args.install:
        install(args); return
    config = json.loads(CONFIG.read_text())
    if args.once:
        collect(config)
    elif args.daemon:
        if config.get('backend') == 'diag':
            diag_daemon(config)
            return
        while True:
            try:
                collect(config)
            except Exception as exc:
                print('liuliang:', str(exc), file=sys.stderr, flush=True)
            time.sleep(INTERVAL)
    else:
        report(config)


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
def diff(c,ip,a,b):
 return c.execute('select coalesce(sum(bytes),0) from traffic where ip=? and ts>? and ts<=?',(ip,a,b)).fetchone()[0]
def report(config):
 DB=str(DATA / "history-v1.db")
 now=time.time();print(col('端口 '+','.join(map(str,config['ports']))+' · 近7天连接',B,C))
 if not os.path.exists(DB):
  if DATA.exists() and not os.access(str(DATA), os.R_OK | os.X_OK):
   print('无法读取流量数据，请使用 root 运行：liuliang');return
  print('(暂无流量数据库记录)');return
 c=sqlite3.connect(DB, timeout=30); rows=[]
 try:
  cols=[r[1] for r in c.execute('PRAGMA table_info(clients)')]
  sel='ip,country,city,isp,last_seen' if 'isp' in cols else 'ip,country,city,last_seen'
  for rec in c.execute(f'select {sel} from clients where last_seen>=? order by last_seen desc',(now-604800,)):
   ip,co,ci=rec[0],rec[1],rec[2]; isp,ls=(rec[3],rec[4]) if len(rec)==5 else ('',rec[3])
   d=diff(c,ip,now-86400,now);w=diff(c,ip,now-604800,now)
   if w<MIN_TRAFFIC_BYTES: continue
   age=max(0,now-float(ls));place=' '.join(x for x in(co,ci) if x) or '未解析';rows.append((ip,isp_display(isp),place,d,w,ls,age))
  if not rows:
   print('(近7天无达到 800KB 的流量记录)');return
  h=['IP','运营商','城市','近24小时','近7天','最近连接'];N=[15,10,8,10,10,19]
  for ip,net,pl,d,w,ls,age in rows:N=[max(N[i],ww(x)) for i,x in enumerate([ip,net,pl,sz(d),sz(w),datetime.fromtimestamp(ls,Z).strftime('%Y-%m-%d %H:%M:%S')])]
  def line(a,m,b):return a+m.join('─'*(n+2) for n in N)+b
  print(line('┌','┬','┐'));print(col('│ '+' │ '.join(cell(x,N[i]) for i,x in enumerate(h))+' │',B,C));print(line('├','┼','┤'))
  for ip,net,pl,d,w,ls,age in rows:
   v=[ip,net,pl,sz(d),sz(w),datetime.fromtimestamp(ls,Z).strftime('%Y-%m-%d %H:%M:%S')];out=[]
   for i,x in enumerate(v):
    st=[D,X] if d<=0 and w<=0 else ([B,G] if i==0 and d>0 else [])
    if i==3 and d>=100*1024**2 or i==4 and w>=1024**3:st=[B,Y]
    if i==5:st=[B,G] if age<=3600 else ([D,X] if age>259200 else [])
    out.append(col(cell(x,N[i]),*st))
   print('│ '+' │ '.join(out)+' │')
  print(line('└','┴','┘'));a=sum(1 for r in rows if r[3]>0 or r[4]>0);print('合计：IP 数 %d · 有流量 IP 数 %d · 近24小时总流量 %s · 近7天总流量 %s'%(len(rows),a,sz(sum(r[3] for r in rows)),sz(sum(r[4] for r in rows))))
 finally:
  c.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print('错误：'+str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        sys.exit(1)
