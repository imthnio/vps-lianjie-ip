import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('liuliang', Path(__file__).with_name('liuliang.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
IP = '8.8.8.8'

class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.c = m.open_db(':memory:')
    def tearDown(self):
        self.c.close()
    def amount(self):
        return self.c.execute('select coalesce(sum(bytes),0) from traffic').fetchone()[0]
    def test_update_merges_newly_detected_ports(self):
        # 老版本漏检的端口（如 hy2 的 UDP 端口、网站端口），更新时自动并入
        args = argparse.Namespace(ports=None, geo=None)
        selected, geo, updating = m.resolve_install({'ports':[40000], 'geo': True}, args, [8080, 40000, 40001])
        self.assertEqual((selected, geo, updating), ([8080, 40000, 40001], True, True))
    def test_update_never_drops_saved_ports(self):
        # 检测不到任何端口时（比如代理正在重启），已有端口一个不能少
        args = argparse.Namespace(ports=None, geo=None)
        selected, _, _ = m.resolve_install({'ports':[40000], 'geo': True}, args, [])
        self.assertEqual(selected, [40000])
        selected, _, _ = m.resolve_install({'ports':[40000], 'geo': True}, args)
        self.assertEqual(selected, [40000])
    def test_update_keeps_saved_ports_and_geo(self):
        args = argparse.Namespace(ports=None, geo=None)
        selected, geo, updating = m.resolve_install({'ports':[443, 8443], 'geo': False}, args)
        self.assertEqual(selected, [443, 8443])
        self.assertFalse(geo)
        self.assertTrue(updating)
    def test_update_flags_override_saved_config(self):
        args = argparse.Namespace(ports='2053', geo='yes')
        selected, geo, updating = m.resolve_install({'ports':[443], 'geo': False}, args)
        self.assertEqual((selected, geo, updating), ([2053], True, True))
    def test_fresh_install_uses_detected_ports(self):
        args = argparse.Namespace(ports=None, geo=None)
        selected, geo, updating = m.resolve_install(None, args, [8443])
        self.assertEqual((selected, geo, updating), ([8443], True, False))
    def test_port_validation(self):
        self.assertEqual(m.ports('443,8443,443'), [443,8443])
        for value in ('0','65536','-1','443; reboot','abc','443,',''):
            with self.assertRaises(ValueError):m.ports(value)
    def test_initial_and_increment(self):
        m.save_sample(self.c,{('up4',IP):(100, None),('down4',IP):(200, None)},1000)
        m.save_sample(self.c,{('up4',IP):(120, None),('down4',IP):(230, None)},1120)
        self.assertEqual(self.amount(),350)
    def test_one_direction_reset(self):
        m.save_sample(self.c,{('up4',IP):(100, None),('down4',IP):(1000, None)},1000)
        m.save_sample(self.c,{('up4',IP):(20, None),('down4',IP):(2000, None)},1120)
        self.assertEqual(self.amount(),2120)
    def test_reboot_with_larger_new_counter(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{('up4',IP):(150, None)},1120,reset=True)
        self.assertEqual(self.amount(),250)
    def test_missing_and_returning_counter(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{},1120)
        m.save_sample(self.c,{('up4',IP):(20, None)},1240)
        self.assertEqual(self.amount(),120)
    def test_one_address_expiring_still_resets_its_baseline(self):
        other='1.1.1.1'
        m.save_sample(self.c,{('up4',IP):(100, None),('up4',other):(100, None)},1000)
        m.save_sample(self.c,{('up4',IP):(100, None)},1120)
        m.save_sample(self.c,{('up4',IP):(100, None),('up4',other):(40, None)},1240)
        self.assertEqual(self.amount(),240)
    def test_idle_does_not_change_activity(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{('up4',IP):(100, None)},1120)
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0],1000)
        self.assertEqual(self.c.execute('select count(*) from traffic').fetchone()[0],1)
    def test_retention(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{},1000+9*86400)
        self.assertEqual(self.amount(),0)
        self.assertEqual(self.c.execute('select count(*) from clients').fetchone()[0],0)
    def test_window_boundaries(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{('up4',IP):(300, None)},1120)
        self.assertEqual(m.diff(self.c,IP,1000,1120),200)
    def test_json_ipv4_ipv6_expires_and_private_filter(self):
        items=[]
        for name,ip,count,expires in [('up4',IP,100,691190),('down4',IP,200,691195),('up6','2606:4700:4700::1111',300,None),('down4','127.0.0.1',400,691200),('down4','224.0.0.1',500,691200),('up4','100.64.1.1',600,691200)]:
            elem={'val':ip,'counter':{'bytes':count,'packets':1}}
            if expires is not None:elem['expires']=expires
            items.append({'set':{'name':name,'elem':[{'elem':elem}]}})
        actual=m.parse_counters({'nftables':items})
        self.assertEqual(actual,{('up4',IP):(100,691190),('down4',IP):(200,691195),('up6','2606:4700:4700::1111'):(300,None)})
    def test_last_seen_uses_expires_not_sample_time(self):
        # 采样时刻 now=10000，但 expires 显示最后一个包是 37 秒前：
        # last_seen 应 ≈ 9963，而不是 10000（原来直接记采样时刻，最多差 120 秒）
        m.save_sample(self.c,{('up4',IP):(100,m.SET_TIMEOUT-37)},10000)
        seen=self.c.execute('select last_seen from clients').fetchone()[0]
        self.assertAlmostEqual(seen,9963,delta=1)
    def test_last_seen_takes_latest_of_four_directions(self):
        m.save_sample(self.c,{('up4',IP):(100,m.SET_TIMEOUT-50),('down4',IP):(200,m.SET_TIMEOUT-10)},10000)
        seen=self.c.execute('select last_seen from clients').fetchone()[0]
        self.assertAlmostEqual(seen,9990,delta=1)
    def test_last_seen_falls_back_to_sample_time_without_expires(self):
        m.save_sample(self.c,{('up4',IP):(100,None)},10000)
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0],10000)
    def test_last_seen_never_goes_backward(self):
        m.save_sample(self.c,{('up4',IP):(100,None)},10000)
        # 后一轮采样 now 更大，但 expires 算出的时间反而更早：last_seen 不应倒退
        m.save_sample(self.c,{('up4',IP):(200,m.SET_TIMEOUT-5000)},10120)
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0],10000)
    def test_parse_duration_number_and_string(self):
        self.assertEqual(m.parse_duration(691200), 691200)
        self.assertEqual(m.parse_duration(691199.7), 691199)
        self.assertEqual(m.parse_duration('691200'), 691200)
        self.assertEqual(m.parse_duration('7d23h59m'), 7*86400+23*3600+59*60)
        self.assertEqual(m.parse_duration('5m'), 300)
        self.assertEqual(m.parse_duration('2h'), 7200)
        self.assertEqual(m.parse_duration('1d'), 86400)
        self.assertEqual(m.parse_duration('26s484ms'), 26)
        self.assertEqual(m.parse_duration('1d2h3m4s500ms'), 86400+7200+180+4)
        self.assertIsNone(m.parse_duration('500ms'))
        self.assertIsNone(m.parse_duration(None))
        self.assertIsNone(m.parse_duration(''))
        self.assertIsNone(m.parse_duration('garbage'))
    def test_parse_counters_accepts_string_expires(self):
        elem = {'val': IP, 'counter': {'bytes': 100, 'packets': 1}, 'expires': '7d23h59m'}
        items = [{'set': {'name': 'up4', 'elem': [{'elem': elem}]}}]
        actual = m.parse_counters({'nftables': items})
        self.assertEqual(actual, {('up4', IP): (100, 7*86400+23*3600+59*60)})
    def test_set_timeout_matches_rules(self):
        self.assertEqual(m.SET_TIMEOUT,8*86400)
        self.assertIn('timeout 8d',m.rules([443]))
    def test_rules_only_count_selected_ports(self):
        s=m.rules([443,8443])
        self.assertIn('tcp dport { 443, 8443 }',s)
        self.assertIn('udp sport { 443, 8443 }',s)
        self.assertNotIn('flush',s);self.assertNotIn('drop',s);self.assertNotIn('forward',s)
    def test_detect_ss_ports(self):
        output='tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=8,fd=3))\n'
        with patch.object(m.shutil,'which',return_value='/bin/ss'),patch.object(m,'run') as run:
            run.return_value.stdout=output
            self.assertEqual(m.listening_ports(),[443])
    def test_detect_netstat_ports(self):
        with patch.object(m.shutil,'which',return_value=None),patch.object(m,'run') as run:
            run.return_value.stdout='tcp 0 0 :::51911 :::* LISTEN 1194/xray\n'
            self.assertEqual(m.listening_ports(),[51911])
    def _ports(self, output, proxy_only=True):
        with patch.object(m.shutil,'which',return_value='/bin/ss'),patch.object(m,'run') as run:
            run.return_value.stdout=output
            return m.detect_ports(proxy_only)
    def test_ignore_proxy_udp_client_sockets(self):
        output='tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=3))\nudp UNCONN 0 0 *:443 *:* users:(("xray",pid=1,fd=4))\nudp UNCONN 0 0 *:54321 *:* users:(("xray",pid=1,fd=8))\n'
        self.assertEqual(self._ports(output), ([443], 'proxy'))
    def test_hysteria_keeps_real_udp_port_only(self):
        output='udp UNCONN 0 0 *:443 *:* users:(("hysteria",pid=1,fd=3))\nudp UNCONN 0 0 1.2.3.4:54321 *:* users:(("hysteria",pid=1,fd=7))\n'
        self.assertEqual(self._ports(output), ([443], 'proxy'))
    def test_hysteria_nat_high_port_kept(self):
        output='udp UNCONN 0 0 *:45678 *:* users:(("hysteria",pid=1,fd=3))\n'
        self.assertEqual(self._ports(output), ([45678], 'proxy'))
    def test_proxy_ports_merged_with_other_service_ports(self):
        # 新行为：代理端口 + 其他对外服务端口一起统计（比如文件传输网站），
        # 不再只保留代理端口。
        output='\n'.join([
            'tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("xray",pid=1,fd=3))',
            'tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=5))',
            'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=3))',
            'tcp LISTEN 0 4096 [::]:8443 [::]:* users:(("sing-box",pid=4,fd=3))',
        ])+'\n'
        self.assertEqual(self._ports(output), ([443, 8443], 'proxy'))
    def test_nat_vps_vless_hy2_and_filesite(self):
        # 用户真实场景：vless TCP 40000 + hy2 UDP 40001 + 文件传输网站 TCP 8080，
        # 三个端口都要被检测到（以前 40001 和 8080 会漏掉）。
        output='\n'.join([
            'tcp LISTEN 0 4096 *:40000 *:* users:(("xray",pid=1,fd=3))',
            'udp UNCONN 0 0 *:40001 *:* users:(("hysteria",pid=2,fd=4))',
            'tcp LISTEN 0 511 *:8080 *:* users:(("python3",pid=3,fd=5))',
            'tcp LISTEN 0 128 *:22 *:* users:(("sshd",pid=4,fd=3))',
        ])+'\n'
        self.assertEqual(self._ports(output), ([8080, 40000, 40001], 'proxy'))
    def test_filesite_without_proxy_uses_service_mode(self):
        output='\n'.join([
            'tcp LISTEN 0 511 *:8080 *:* users:(("python3",pid=3,fd=5))',
            'tcp LISTEN 0 128 *:22 *:* users:(("sshd",pid=4,fd=3))',
        ])+'\n'
        self.assertEqual(self._ports(output), ([8080], 'service'))
    def test_socket_listing_covers_udp(self):
        # 回归测试：read_socket_table 必须同时列出 TCP 和 UDP，
        # 否则纯 UDP 代理（如 hy2）的端口永远检测不到。
        seen = []
        def fake(args, **kwargs):
            seen.append(' '.join(args))
            class Result:
                stdout = ''
            return Result()
        with patch.object(m.shutil, 'which', return_value='/bin/ss'), patch.object(m, 'run', side_effect=fake):
            m.read_socket_table()
        self.assertTrue(any('-lntup' in cmd for cmd in seen), seen)
        self.assertTrue(any('-lnup' in cmd and '-lntup' not in cmd for cmd in seen), seen)
    def test_only_loopback_proxy_falls_through_to_frontend(self):
        output='\n'.join([
            'tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("xray",pid=1,fd=3))',
            'tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=5))',
            'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=3))',
        ])+'\n'
        self.assertEqual(self._ports(output), ([443], 'frontend'))
    def test_public_and_loopback_proxy_ports(self):
        output='tcp LISTEN 0 4096 127.0.0.1:62789 0.0.0.0:* users:(("xray",pid=1,fd=6))\ntcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=1,fd=3))\n'
        self.assertEqual(self._ports(output), ([443], 'proxy'))
    def test_fallback_skips_ssh_ephemeral_udp_and_loopback(self):
        output='\n'.join([
            'tcp LISTEN 0 128 *:22 *:* users:(("sshd",pid=1,fd=3))',
            'tcp LISTEN 0 511 *:80 *:* users:(("nginx",pid=2,fd=4))',
            'udp UNCONN 0 0 *:54321 *:* users:(("python3",pid=3,fd=5))',
            'udp UNCONN 0 0 *:68 *:* users:(("dhclient",pid=4,fd=6))',
            'udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=5,fd=8))',
        ])+'\n'
        self.assertEqual(self._ports(output, proxy_only=False), ([68, 80], 'fallback'))
    def test_ss_without_H_is_retried(self):
        def fake(args, **kwargs):
            if '-H' in args:
                raise m.subprocess.CalledProcessError(1, args)
            class Result:
                stdout='tcp LISTEN 0 4096 *:8443 *:* users:(("sing-box",pid=1,fd=3))\n'
            return Result()
        with patch.object(m.shutil,'which',return_value='/bin/ss'),patch.object(m,'run',side_effect=fake):
            self.assertEqual(m.listening_ports(),[8443])
    def test_report_says_root_when_data_dir_is_unreadable(self):
        with tempfile.TemporaryDirectory() as temp:
            blocked = Path(temp)/'liuliang'
            blocked.mkdir()
            blocked.chmod(0)
            try:
                out=io.StringIO()
                with patch.object(m,'DATA',blocked),contextlib.redirect_stdout(out):
                    m.report({'ports':[443],'geo':True})
                self.assertIn('root', out.getvalue())
            finally:
                blocked.chmod(0o700)
    def test_report_unicode(self):
        with tempfile.TemporaryDirectory() as temp:
            db=m.open_db(Path(temp)/'history-v1.db')
            m.save_sample(db,{('up6','2606:4700:4700::1111'):(900*1024, None)},m.time.time())
            db.execute("update clients set city='测试城市',country='US'");db.commit();db.close()
            out=io.StringIO()
            with patch.object(m,'DATA',Path(temp)),contextlib.redirect_stdout(out):m.report({'ports':[443],'geo':True})
            self.assertIn('测试城市',out.getvalue());self.assertIn('900',out.getvalue())
    def test_report_filters_below_800kb(self):
        with tempfile.TemporaryDirectory() as temp:
            now=m.time.time()
            db=m.open_db(Path(temp)/'history-v1.db')
            # 799KB -> filtered out; 800KB -> kept (boundary inclusive)
            m.save_sample(db,{('up4','1.1.1.1'):(799*1024, None)},now)
            m.save_sample(db,{('up4','2.2.2.2'):(800*1024, None)},now)
            db.close()
            out=io.StringIO()
            with patch.object(m,'DATA',Path(temp)),contextlib.redirect_stdout(out):m.report({'ports':[443],'geo':True,'min_kb':800})
            text=out.getvalue()
            self.assertNotIn('1.1.1.1',text)
            self.assertIn('2.2.2.2',text)
    def test_nft_denied_falls_back_to_connection_sampling(self):
        def fake(args, **kwargs):
            if args[0] == 'nft':
                raise m.subprocess.CalledProcessError(
                    1, args,
                    stderr='netlink: Error: cache initialization failed: Operation not permitted\n')
            return m.subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        with patch.object(m, 'run', side_effect=fake), \
             patch.object(m, 'conntrack_text', return_value=''), \
             patch.object(m, 'raw_possible', return_value=False), \
             patch.object(m.shutil, 'which', return_value='/sbin/ss'):
            backend, sources, detail = m.probe_backend('table inet liuliang_v1 { }')
        self.assertEqual(backend, 'diag')
        self.assertEqual(sources['tcp'], 'ss')
        self.assertEqual(sources['udp'], 'conntrack')
        self.assertIn('Operation not permitted', detail)
    def test_sampling_unavailable_still_raises(self):
        def fake(args, **kwargs):
            raise m.subprocess.CalledProcessError(1, args, stderr='Operation not permitted\n')
        with patch.object(m, 'run', side_effect=fake), \
             patch.object(m, 'conntrack_text', return_value=None), \
             patch.object(m, 'raw_possible', return_value=False), \
             patch.object(m.shutil, 'which', return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                m.probe_backend('table inet liuliang_v1 { }')
        self.assertIn('nftables', str(ctx.exception))
    def test_nft_backend_when_usable(self):
        with patch.object(m, 'run') as run:
            run.return_value.stdout = ''
            backend, sources, detail = m.probe_backend('table inet liuliang_v1 { }')
        self.assertEqual((backend, sources, detail), ('nft', {}, ''))
    def test_ss_falls_back_when_H_is_unsupported(self):
        def fake(args, **kwargs):
            if args[:2] == ['ss', '-H']:
                raise m.subprocess.CalledProcessError(1, args, stderr='unrecognized')
            self.assertEqual(args, ['ss', '-tin'])
            return m.subprocess.CompletedProcess(args, 0, stdout='ESTAB 0 0 10.0.0.1:443 8.8.8.8:9\n\t bytes_sent:3 bytes_received:4\n', stderr='')
        with patch.object(m, 'run', side_effect=fake):
            flows = m.parse_ss(m.read_ss(), [443])
        self.assertEqual(flows['tcp|10.0.0.1|443|8.8.8.8|9'], ('8.8.8.8', 4, 3))
    def test_parse_ss_counts_tcp_payload_and_skips_ssh_private(self):
        text = '\n'.join([
            '0 0 10.0.0.8:443 8.8.8.8:40000',
            '\t cubic bytes_sent:1000 bytes_received:2000',
            '0 0 10.0.0.8:22 1.1.1.1:40001',
            '\t cubic bytes_sent:9 bytes_received:9',
            '0 0 10.0.0.8:443 192.168.1.9:40002',
            '\t cubic bytes_sent:50 bytes_received:50',
            '0 0 [2001:db8::1]:443 [2606:4700:4700::1111]:50000',
            '\t bytes_acked:10 bytes_received:20',
            '0 0 10.0.0.8:443 [::ffff:8.8.4.4]:50001',
            '\t bytes_sent:7 bytes_received:8',
            'LISTEN 0 128 0.0.0.0:443 0.0.0.0:*',
        ])
        flows = m.parse_ss(text, [443])
        self.assertEqual(flows['tcp|10.0.0.8|443|8.8.8.8|40000'], ('8.8.8.8', 2000, 1000))
        self.assertEqual(flows['tcp|2001:db8::1|443|2606:4700:4700::1111|50000'], ('2606:4700:4700::1111', 20, 10))
        self.assertEqual(flows['tcp|10.0.0.8|443|::ffff:8.8.4.4|50001'], ('8.8.4.4', 8, 7))
        self.assertEqual(len(flows), 3)
    def test_parse_conntrack_udp_only_when_tcp_disabled(self):
        text = '\n'.join([
            'ipv4 2 udp 17 20 src=8.8.8.8 dst=10.0.0.8 sport=1111 dport=443 packets=2 bytes=300 src=10.0.0.8 dst=8.8.8.8 sport=443 dport=1111 packets=1 bytes=100 mark=0 use=1',
            'ipv4 2 tcp 6 100 ESTABLISHED src=1.1.1.1 dst=10.0.0.8 sport=2222 dport=443 packets=2 bytes=99999 src=10.0.0.8 dst=1.1.1.1 sport=443 dport=2222 packets=1 bytes=1 mark=0 use=1',
            'ipv4 2 udp 17 20 src=10.0.0.9 dst=10.0.0.8 sport=1111 dport=443 packets=1 bytes=10 src=10.0.0.8 dst=10.0.0.9 sport=443 dport=1111 packets=1 bytes=10 mark=0 use=1',
        ])
        flows = m.parse_conntrack(text, [443], tcp=False, udp=True)
        self.assertEqual(list(flows.values()), [('8.8.8.8', 300, 100)])
    def test_account_flows_delta_reuse_and_linger(self):
        prev = {'tcp|a': (100, 50, 0)}
        baselines, activity = m.account_flows(prev, {'tcp|a': ('8.8.8.8', 140, 80), 'tcp|b': ('1.1.1.1', 5, 7)}, 10)
        self.assertEqual(activity['8.8.8.8'], 70)
        self.assertEqual(activity['1.1.1.1'], 12)
        self.assertIn('tcp|a', baselines)
        _, replay = m.account_flows(baselines, {'tcp|a': ('8.8.8.8', 10, 4)}, 20)
        self.assertEqual(replay['8.8.8.8'], 14)
        kept, idle = m.account_flows(prev, {}, 50)
        self.assertEqual(kept, prev)
        self.assertEqual(idle, {})
        dropped, _ = m.account_flows(prev, {'tcp|b': ('1.1.1.1', 1, 1)}, prev['tcp|a'][2] + m.FLOW_KEEP + 1)
        self.assertNotIn('tcp|a', dropped)
    def test_account_packet_udp_directions(self):
        def packet(src, dst, sport, dport):
            payload = b'abc'
            udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
            total = 20 + len(udp)
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
            return ip + udp
        up_ip, up_n = m.account_packet(packet('8.8.8.8', '10.0.0.8', 1111, 443), {443}, False, True)
        down_ip, down_n = m.account_packet(packet('10.0.0.8', '8.8.8.8', 443, 1111), {443}, False, True)
        ignored, ignored_n = m.account_packet(packet('8.8.8.8', '10.0.0.8', 1111, 443), {443}, False, False)
        self.assertEqual((up_ip, up_n), ('8.8.8.8', 31))
        self.assertEqual((down_ip, down_n), ('8.8.8.8', 31))
        self.assertEqual((ignored, ignored_n), (None, 0))
    def test_diag_tick_flushes_deltas_once(self):
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp)
            lock = data / 'lock'
            flows = {'tcp|a': ('8.8.8.8', 1000, 500)}
            cfg = {'ports': [443], 'diag': {'tcp': 'ss', 'udp': None}}
            with patch.object(m, 'DATA', data), patch.object(m, 'LOCK', lock), \
                 patch.object(m, 'read_flow_snapshot', return_value=flows):
                m.diag_tick(cfg, True)
            db = m.open_db(data / 'history-v1.db')
            self.assertEqual(db.execute('select coalesce(sum(bytes),0) from traffic').fetchone()[0], 1500)
            db.close()
            with patch.object(m, 'DATA', data), patch.object(m, 'LOCK', lock), \
                 patch.object(m, 'read_flow_snapshot', return_value=flows):
                m.diag_tick(cfg, True)
            db = m.open_db(data / 'history-v1.db')
            self.assertEqual(db.execute('select coalesce(sum(bytes),0) from traffic').fetchone()[0], 1500)
            db.close()
            grown = {'tcp|a': ('8.8.8.8', 1100, 550)}
            with patch.object(m, 'DATA', data), patch.object(m, 'LOCK', lock), \
                 patch.object(m, 'read_flow_snapshot', return_value=grown):
                m.diag_tick(cfg, True)
            db = m.open_db(data / 'history-v1.db')
            self.assertEqual(db.execute('select coalesce(sum(bytes),0) from traffic').fetchone()[0], 1650)
            db.close()
    def test_diag_switch_does_not_replay_old_totals(self):
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp)
            lock = data / 'lock'
            db = m.open_db(data / 'history-v1.db')
            m.save_sample(db, {('up4', '8.8.8.8'): (5000, None)}, m.time.time())
            db.close()
            cfg = {'ports': [443], 'diag': {'tcp': 'ss', 'udp': None}}
            with patch.object(m, 'DATA', data), patch.object(m, 'LOCK', lock), \
                 patch.object(m, 'read_flow_snapshot', return_value={'tcp|a': ('8.8.8.8', 9000, 1000)}):
                m.diag_tick(cfg, True)
            db = m.open_db(data / 'history-v1.db')
            self.assertEqual(db.execute('select coalesce(sum(bytes),0) from traffic').fetchone()[0], 5000)
            db.close()
            with patch.object(m, 'DATA', data), patch.object(m, 'LOCK', lock), \
                 patch.object(m, 'read_flow_snapshot', return_value={'tcp|a': ('8.8.8.8', 9400, 1200)}):
                m.diag_tick(cfg, True)
            db = m.open_db(data / 'history-v1.db')
            self.assertEqual(db.execute('select coalesce(sum(bytes),0) from traffic').fetchone()[0], 5600)
            db.close()
    # ---- 网站（文件分享网盘）访客 ----
    def test_rules_web_sets_only_when_web_ports(self):
        self.assertNotIn('web4', m.rules([443]))
        s = m.rules([443, 18080], [18080, 9999])
        self.assertIn('set web4', s); self.assertIn('set web6', s)
        self.assertIn('tcp dport { 18080 } update @web4 { ip saddr counter }', s)
        self.assertIn('tcp sport { 18080 } update @web6 { ip6 daddr counter }', s)
        self.assertNotIn('9999', s)
    def test_parse_counters_reads_web_sets(self):
        doc = {'nftables': [{'set': {'name': 'web4', 'elem': [{'elem': {'val': '8.8.8.8', 'counter': {'bytes': 42}}}]}}]}
        self.assertEqual(m.parse_counters(doc), {('web4', '8.8.8.8'): (42, None)})
    def test_save_sample_records_web_share(self):
        m.save_sample(self.c, {('up4', IP): (1000, None), ('down4', IP): (3000, None), ('web4', IP): (2500, None)}, 100)
        self.assertEqual(list(self.c.execute('select bytes, web from traffic')), [(4000, 2500)])
        m.save_sample(self.c, {('up4', IP): (1100, None), ('down4', IP): (3000, None), ('web4', IP): (2500, None)}, 200)
        self.assertEqual(list(self.c.execute('select bytes, web from traffic order by ts')), [(4000, 2500), (100, 0)])
    def test_old_database_gains_web_column(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'h.db'
            old = sqlite3.connect(str(path))
            old.executescript("CREATE TABLE traffic(ts REAL NOT NULL, ip TEXT NOT NULL, bytes INTEGER NOT NULL);"
                              "CREATE TABLE pending(ip TEXT PRIMARY KEY, bytes INTEGER NOT NULL, last_seen REAL NOT NULL);"
                              "INSERT INTO traffic VALUES(1, '8.8.8.8', 5);")
            old.commit(); old.close()
            db = m.open_db(path)
            self.assertEqual(list(db.execute('select bytes, web from traffic')), [(5, 0)])
            m.add_pending(db, {IP: 10}, 2, {IP: 4}); m.take_pending(db, 3)
            self.assertEqual(list(db.execute('select bytes, web from traffic where ts=3')), [(10, 4)])
            db.close()
    def _report(self, samples, config=None):
        with tempfile.TemporaryDirectory() as temp:
            db = m.open_db(Path(temp) / 'history-v1.db')
            for sample in samples:
                m.save_sample(db, sample, m.time.time())
            db.close()
            out = io.StringIO()
            with patch.object(m, 'DATA', Path(temp)), contextlib.redirect_stdout(out):
                m.report(config or {'ports': [443, 18080], 'geo': True, 'web': [18080]})
            return out.getvalue()
    def test_report_shows_small_web_visitors_and_hides_scanners(self):
        text = self._report([{('up4', '1.1.1.1'): (10 * 1024, None), ('down4', '1.1.1.1'): (30 * 1024, None),
                              ('web4', '1.1.1.1'): (40 * 1024, None),
                              ('up4', '2.2.2.2'): (1024, None), ('down4', '2.2.2.2'): (3 * 1024, None),
                              ('web4', '2.2.2.2'): (4 * 1024, None),
                              ('up4', '3.3.3.3'): (900 * 1024, None)}])
        self.assertIn('1.1.1.1', text); self.assertNotIn('2.2.2.2', text); self.assertIn('3.3.3.3', text)
        self.assertIn('访问', text); self.assertIn('网站', text); self.assertIn('节点', text)
    def test_report_without_web_keeps_old_columns(self):
        text = self._report([{('up4', '3.3.3.3'): (900 * 1024, None)}], {'ports': [443], 'geo': True})
        self.assertIn('3.3.3.3', text); self.assertNotIn('访问', text)
    def test_follow_ports_needs_two_scans_and_respects_manual(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg_path = Path(temp) / 'config.json'
            cfg = {'ports': [443], 'web': [], 'auto': True}
            with patch.object(m, 'CONFIG', cfg_path), \
                 patch.object(m, 'scan_ports', return_value=([443, 18080], 'proxy', [18080])):
                seen, changed = m.follow_ports(cfg, set())
                self.assertFalse(changed); self.assertEqual(cfg['ports'], [443])
                seen, changed = m.follow_ports(cfg, seen)
                self.assertTrue(changed)
                self.assertEqual((cfg['ports'], cfg['web']), ([443, 18080], [18080]))
                self.assertEqual(json.loads(cfg_path.read_text())['ports'], [443, 18080])
                self.assertFalse(m.follow_ports(cfg, seen)[1])
                manual = {'ports': [443], 'web': [], 'auto': False}
                self.assertFalse(m.follow_ports(manual, {443, 18080})[1])
                self.assertEqual(manual['ports'], [443])
    def test_follow_ports_never_drops_ports(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = {'ports': [443, 8443], 'web': [8443], 'auto': True}
            with patch.object(m, 'CONFIG', Path(temp) / 'c.json'), \
                 patch.object(m, 'scan_ports', return_value=([], 'none', [])):
                self.assertFalse(m.follow_ports(cfg, {443})[1])
            self.assertEqual(cfg['ports'], [443, 8443])
    def test_closed_watcher_parses_ss_events(self):
        lines = [
            'UNCONN 1      0      45.76.1.1:18080 8.8.8.8:60484\n',
            '\t wscale:7,7 rto:204 cwnd:158 bytes_sent:205070 bytes_acked:205071 bytes_received:134 segs_out:176\n',
            'UNCONN 0      1      127.0.0.1:38020 127.0.0.1:9223\n',
            '\t rto:1000 mss:524 cwnd:10 segs_out:1\n',
            'UNCONN 1      0      45.76.1.1:22 8.8.8.8:5000\n',
            '\t bytes_sent:9 bytes_received:9\n',
        ]
        class Proc:
            stdout = iter(lines)
            def kill(self): pass
            def wait(self): pass
        w = m.ClosedWatcher([18080])
        with patch.object(m.subprocess, 'Popen', return_value=Proc()):
            w._follow(['ss', '-E', '-H', '-tin'])
        self.assertEqual(w.drain(), {'tcp|45.76.1.1|18080|8.8.8.8|60484': ('8.8.8.8', 134, 205070)})
        self.assertEqual(w.drain(), {})
    def test_diag_tick_counts_short_connections_once(self):
        # 2 秒采样之间就结束的连接只能从 ss -E 拿到；采样见过的连接关闭时只补差额。
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp); lock = data / 'lock'
            cfg = {'ports': [18080], 'web': [18080], 'diag': {'tcp': 'ss', 'udp': None}}
            class W:
                def __init__(self, d): self.d = d
                def drain(self):
                    d, self.d = self.d, {}
                    return d
            short = 'tcp|45.76.1.1|18080|8.8.8.8|1000'
            long = 'tcp|45.76.1.1|18080|8.8.8.8|2000'
            def tick(snapshot, closed):
                with patch.object(m, 'DATA', data), patch.object(m, 'LOCK', lock), \
                     patch.object(m, 'read_flow_snapshot', return_value=snapshot):
                    m.diag_tick(cfg, True, None, W(closed))
            tick({}, {short: ('8.8.8.8', 300, 700)})
            tick({long: ('8.8.8.8', 100, 1000)}, {})
            tick({}, {long: ('8.8.8.8', 150, 5000)})
            tick({}, {})
            db = m.open_db(data / 'history-v1.db')
            self.assertEqual(db.execute('select sum(bytes), sum(web) from traffic').fetchone(), (1000 + 1100 + 4050, 1000 + 1100 + 4050))
            db.close()
    def test_web_activity_only_web_ports(self):
        cur = {'tcp|h|18080|8.8.8.8|1': ('8.8.8.8', 10, 20), 'tcp|h|443|8.8.8.8|2': ('8.8.8.8', 100, 200),
               'ctcp|8.8.4.4|5|h|18080': ('8.8.4.4', 1, 2)}
        self.assertEqual(m.web_activity({}, cur, [18080], 0), {'8.8.8.8': 30, '8.8.4.4': 3})
        self.assertEqual(m.web_activity({}, cur, None, 0), {})
    # ---- Cloudflare 后面的网站：从本机反代转发的请求头认真实访客 ----
    @staticmethod
    def _lo_packet(src_port, dst_port, payload=b'', flags=0x18, v6=False):
        tcp = struct.pack('!HHIIBBHHH', src_port, dst_port, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
        if v6:
            return struct.pack('!IHBB', 6 << 28, len(tcp), 6, 64) + socket.inet_pton(socket.AF_INET6, '::1') * 2 + tcp
        return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                           socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1')) + tcp
    def test_is_cloudflare(self):
        for ip in ('172.70.1.1', '162.158.9.9', '104.16.0.1', '2606:4700::1', '::ffff:172.70.1.1'):
            self.assertTrue(m.is_cloudflare(ip), ip)
        for ip in ('8.8.8.8', '1.0.0.1', '2001:4860::8888', 'x', ''):
            self.assertFalse(m.is_cloudflare(ip), ip)
    def test_header_ip_rules(self):
        h = lambda *lines: ('GET / HTTP/1.1\r\nHost: a\r\n' + ''.join(l + '\r\n' for l in lines) + '\r\n').encode()
        # 橙色云 + 本机 Caddy：XFF 最后一跳是 Cloudflare
        self.assertEqual(m.header_ip(h('CF-Connecting-IP: 9.9.9.9', 'X-Forwarded-For: 9.9.9.9, 172.70.1.1')), '9.9.9.9')
        # Cloudflare Tunnel：cloudflared 原样转发，XFF 就是访客
        self.assertEqual(m.header_ip(h('Cf-Connecting-Ip: 2001:4860::8888', 'X-Forwarded-For: 2001:4860::8888')), '2001:4860::8888')
        # 没有 XFF 的本机反代
        self.assertEqual(m.header_ip(h('cf-connecting-ip: 9.9.9.9')), '9.9.9.9')
        # 访客直连 Caddy、自己伪造 CF 头：最后一跳是他自己，不采信
        self.assertIsNone(m.header_ip(h('CF-Connecting-IP: 9.9.9.9', 'X-Forwarded-For: 8.8.8.8')))
        # 没有 CF 头 / 内网地址 / 乱写的值
        self.assertIsNone(m.header_ip(h('X-Forwarded-For: 172.70.1.1')))
        self.assertIsNone(m.header_ip(h('CF-Connecting-IP: 10.0.0.1')))
        self.assertIsNone(m.header_ip(h('CF-Connecting-IP: <script>')))
        # 请求体里的同名字段不算
        self.assertIsNone(m.header_ip(b'POST / HTTP/1.1\r\nHost: a\r\n\r\nCF-Connecting-IP: 9.9.9.9\r\n'))
    def test_sniffer_counts_bytes_for_real_visitor(self):
        s = m.RealIPSniffer([18080])
        req = b'GET /s/abc HTTP/1.1\r\nHost: x\r\nCF-Connecting-IP: 9.9.9.9\r\nX-Forwarded-For: 9.9.9.9, 172.70.1.1\r\n\r\n'
        p1 = self._lo_packet(40000, 18080, req)
        p2 = self._lo_packet(18080, 40000, b'x' * 1000)
        s.feed(p1, 10); s.feed(p2, 11)
        s.feed(self._lo_packet(40001, 9999, req), 12)  # 别的端口不看
        data, seen, n = s.drain()
        self.assertEqual(data, {'9.9.9.9': len(p1) + len(p2)})
        self.assertEqual((seen, n), ({'9.9.9.9': 11}, 1))
        self.assertEqual(s.drain()[0], {})
    def test_sniffer_keepalive_switches_visitor_and_split_headers(self):
        s = m.RealIPSniffer([18080])
        a = b'GET / HTTP/1.1\r\nCF-Connecting-IP: 9.9.9.9\r\n\r\n'
        s.feed(self._lo_packet(40000, 18080, a, v6=True), 1)
        s.feed(self._lo_packet(18080, 40000, b'y' * 100, v6=True), 2)
        # 同一条长连接，下一个请求是别的访客，请求头还分成了两个包
        s.feed(self._lo_packet(40000, 18080, b'POST /up HTTP/1.1\r\nHost: x\r\nCF-Conn', v6=True), 3)
        s.feed(self._lo_packet(40000, 18080, b'ecting-IP: 8.8.4.4\r\n\r\nbody', v6=True), 4)
        s.feed(self._lo_packet(40000, 18080, b'z' * 500, v6=True), 5)
        # 再下一个请求没有 CF 头（直连访客，公网端口已经数过）：不再记给上一个人
        s.feed(self._lo_packet(40000, 18080, b'GET / HTTP/1.1\r\nHost: x\r\n\r\n', v6=True), 6)
        s.feed(self._lo_packet(18080, 40000, b'w' * 300, v6=True), 7)
        data, _seen, n = s.drain()
        self.assertEqual(set(data), {'9.9.9.9', '8.8.4.4'})
        self.assertEqual(data['9.9.9.9'], 2 * 40 + 2 * 20 + len(a) + 100)
        self.assertEqual(data['8.8.4.4'], 3 * 40 + 3 * 20 + len(b'POST /up HTTP/1.1\r\nHost: x\r\nCF-Conn') + len(b'ecting-IP: 8.8.4.4\r\n\r\nbody') + 500)
        self.assertEqual(n, 2)
        # FIN 之后流表清掉
        s.feed(self._lo_packet(18080, 40000, b'', flags=0x11, v6=True), 8)
        self.assertEqual(s.flows, {})
    def test_sniffer_gc_drops_idle_flows(self):
        s = m.RealIPSniffer([18080])
        s.feed(self._lo_packet(40000, 18080, b'GET / HTTP/1.1\r\nCF-Connecting-IP: 9.9.9.9\r\n\r\n'), 0)
        s.gc(10); self.assertEqual(len(s.flows), 1)
        s.gc(1000); self.assertEqual(s.flows, {})
    def test_save_realip_writes_web_traffic(self):
        s = m.RealIPSniffer([18080])
        s.pending, s.seen, s.requests = {'9.9.9.9': 30000}, {'9.9.9.9': 50.0}, 3
        m.save_realip(self.c, s, 60); m.take_pending(self.c, 60)
        self.assertEqual(list(self.c.execute('select ip,bytes,web from traffic')), [('9.9.9.9', 30000, 30000)])
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0], 50.0)
        self.assertEqual(self.c.execute("select value from metadata where key='realip_last'").fetchone()[0], '60')
        m.save_realip(self.c, None, 70)  # 没有抓包也不出错
    def test_backend_ports_include_loopback_web_apps(self):
        text = '\n'.join([
            'tcp LISTEN 0 128 127.0.0.1:18080 0.0.0.0:* users:(("python3",pid=1,fd=3))',
            'tcp LISTEN 0 128 *:443 *:* users:(("caddy",pid=2,fd=3))',
            'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=3))',
            'tcp LISTEN 0 128 127.0.0.1:10085 0.0.0.0:* users:(("xray",pid=4,fd=3))',
        ])
        self.assertEqual(m.backend_ports(text), [443, 18080])
    def test_report_hides_cloudflare_and_shows_real_visitor(self):
        now = m.time.time()
        with tempfile.TemporaryDirectory() as temp:
            db = m.open_db(Path(temp) / 'history-v1.db')
            m.save_sample(db, {('up4', '172.70.1.1'): (900 * 1024, None), ('web4', '172.70.1.1'): (900 * 1024, None)}, now)
            m.add_pending(db, {'9.9.9.9': 25 * 1024}, now, {'9.9.9.9': 25 * 1024}); m.take_pending(db, now)
            db.commit(); db.close()
            def run(**kw):
                out = io.StringIO()
                with patch.object(m, 'DATA', Path(temp)), contextlib.redirect_stdout(out):
                    m.report({'ports': [443], 'geo': True, 'web': [443]}, **kw)
                return out.getvalue()
            text = run()
            self.assertIn('9.9.9.9', text); self.assertNotIn('172.70.1.1', text)
            self.assertIn('已隐藏 1 个 Cloudflare', text); self.assertIn('IP 数 1 ', text)
            text = run(show_all=True)
            self.assertIn('172.70.1.1', text); self.assertIn('CF节点', text); self.assertIn('IP 数 1 ', text)
            text = run(web_only=True)
            self.assertIn('9.9.9.9', text); self.assertIn('网站访客', text)
    def test_report_web_only_has_no_threshold(self):
        text = self._report([{('up4', '8.8.8.8'): (1024, None), ('web4', '8.8.8.8'): (1024, None)},
                             {('up4', '8.8.8.8'): (2048, None), ('web4', '8.8.8.8'): (2048, None)}])
        self.assertNotIn('8.8.8.8', text)
        with tempfile.TemporaryDirectory() as temp:
            db = m.open_db(Path(temp) / 'history-v1.db')
            m.save_sample(db, {('up4', '8.8.8.8'): (0, None), ('web4', '8.8.8.8'): (0, None)}, m.time.time())
            m.save_sample(db, {('up4', '8.8.8.8'): (2048, None), ('web4', '8.8.8.8'): (2048, None)}, m.time.time())
            db.close(); out = io.StringIO()
            with patch.object(m, 'DATA', Path(temp)), contextlib.redirect_stdout(out):
                m.report({'ports': [443], 'web': [443]}, web_only=True)
            self.assertIn('8.8.8.8', out.getvalue())
    def test_payload_is_self_contained(self):
        s=Path(__file__).with_name('install.sh').read_text()
        payload=s.split("<<'LIULIANG_PYTHON'\n",1)[1].split('\nLIULIANG_PYTHON\n',1)[0]+'\n'
        self.assertEqual(payload,Path(__file__).with_name('liuliang.py').read_text())

class SiteTests(unittest.TestCase):
    """每个 IP 访问了哪些应用/网站、各用了多少流量。"""
    XRAY = '2026/10/08 12:00:00.123456 from 8.8.8.8:50001 accepted tcp:www.youtube.com:443 [vless-in -> direct] email: a'
    def ss(self, port, sent, received, peer='8.8.8.8'):
        return ('ESTAB 0 0 [::ffff:10.0.0.2]:443 [::ffff:%s]:%d\n\t cubic bytes_sent:%d bytes_received:%d\n'
                % (peer, port, sent, received))
    def test_parse_xray_and_singbox_logs(self):
        p = m.AccessParser()
        self.assertEqual(p.feed(self.XRAY), ('8.8.8.8', 50001, 'www.youtube.com'))
        self.assertEqual(p.feed('2026/10/08 12:00:00 1.1.1.1:6000 accepted tcp:149.154.167.51:443 [in >> out]'),
                         ('1.1.1.1', 6000, '149.154.167.51'))
        self.assertEqual(p.feed('2026/10/08 12:00:00 from tcp:[2606:4700::1]:7000 accepted udp:Chat.OpenAI.com.:443'),
                         ('2606:4700::1', 7000, 'chat.openai.com'))
        self.assertIsNone(p.feed('2026/10/08 12:00:00 from 8.8.8.8:1 accepted udp:1.1.1.1:53 [in -> dns]'))
        self.assertIsNone(p.feed('2026/10/08 12:00:00 from 127.0.0.1:1 accepted tcp:google.com:443'))
        self.assertIsNone(p.feed('2026/10/08 12:00:00 [Info] app/dispatcher: sniffed domain: google.com'))
        self.assertIsNone(p.feed('\x1b[36mINFO\x1b[0m [123 0ms] inbound/vless[in]: inbound connection from 9.9.9.9:4000'))
        self.assertEqual(p.feed('+0800 2026-10-08 12:00:00 INFO [123 5ms] inbound/vless[in]: inbound connection to www.netflix.com:443'),
                         ('9.9.9.9', 4000, 'www.netflix.com'))
        self.assertIsNone(p.feed('INFO [124 0ms] inbound/hysteria2[hy]: inbound packet connection to x.com:443'))
    def test_site_label(self):
        self.assertEqual(m.site_label('rr3---sn-a5m.googlevideo.com'), 'YouTube')
        self.assertEqual(m.site_label('youtubei.googleapis.com'), 'YouTube')
        self.assertEqual(m.site_label('www.googleapis.com'), 'Google')
        self.assertEqual(m.site_label('gemini.google.com'), 'Gemini')
        self.assertEqual(m.site_label('149.154.167.51'), 'Telegram')
        self.assertEqual(m.site_label('1.2.3.4'), '1.2.3.4')
        self.assertEqual(m.site_label('cdn.static.example.com'), 'example.com')
        self.assertEqual(m.site_label('news.bbc.co.uk'), 'bbc.co.uk')
    def test_tracker_counts_bytes_per_site(self):
        t = m.SiteTracker([443])
        t.tick(100, [self.XRAY], m.parse_ss(self.ss(50001, 1000, 200), [443]), {})
        t.tick(102, [], m.parse_ss(self.ss(50001, 5000, 300), [443]), {})
        # 另一条连接还没有日志：不算
        t.tick(104, [], m.parse_ss(self.ss(50001, 5000, 300) + self.ss(50002, 999, 1), [443]), {})
        data, _ = t.drain()
        self.assertEqual(data[('8.8.8.8', 'www.youtube.com')][:2], [5300, 1])
        self.assertNotIn(('8.8.8.8', None), data)
    def test_tracker_short_connection_closed_before_log(self):
        t = m.SiteTracker([443])
        closed = m.parse_ss(self.ss(50001, 7000, 100), [443])
        t.tick(100, [], {}, closed)
        t.tick(101, [self.XRAY], {}, {})
        data, _ = t.drain()
        self.assertEqual(data[('8.8.8.8', 'www.youtube.com')][:2], [7100, 1])
    def test_tracker_mux_only_counts_hits(self):
        t = m.SiteTracker([443])
        two = [self.XRAY, self.XRAY.replace('www.youtube.com', 'www.netflix.com')]
        t.tick(100, two, m.parse_ss(self.ss(50001, 9000, 0), [443]), {})
        data, _ = t.drain()
        self.assertEqual(data[('8.8.8.8', 'www.youtube.com')][:2], [0, 1])
        self.assertEqual(data[('8.8.8.8', 'www.netflix.com')][:2], [0, 1])
    def test_tracker_port_reuse_after_close(self):
        t = m.SiteTracker([443])
        t.tick(100, [self.XRAY], m.parse_ss(self.ss(50001, 100, 0), [443]), {})
        t.tick(102, [], {}, {})
        t.tick(200, [self.XRAY.replace('www.youtube.com', 'github.com')], m.parse_ss(self.ss(50001, 50, 0), [443]), {})
        data, _ = t.drain()
        self.assertEqual(data[('8.8.8.8', 'www.youtube.com')][0], 100)
        self.assertEqual(data[('8.8.8.8', 'github.com')][0], 50)
    def _db(self, temp, tracker=None, traffic=0):
        db = m.open_db(Path(temp) / 'history-v1.db')
        now = m.time.time()
        if traffic:
            m.save_sample(db, {('up4', '8.8.8.8'): (traffic, None)}, now)
        if tracker is not None:
            m.save_sites(db, tracker, now)
        db.commit(); db.close()
    def _site_report(self, temp, ip='8.8.8.8', **kw):
        out = io.StringIO()
        with patch.object(m, 'DATA', Path(temp)), contextlib.redirect_stdout(out):
            m.site_report(ip, {'ports': [443]}, **kw)
        return out.getvalue()
    def test_site_report_table(self):
        t = m.SiteTracker([443])
        t.status = {'sources': ['file:/var/log/xray/access.log'], 'notes': []}
        lines = [self.XRAY,
                 self.XRAY.replace('50001', '50002').replace('www.youtube.com', 'rr1.googlevideo.com'),
                 self.XRAY.replace('50001', '50003').replace('www.youtube.com', 'github.com')]
        flows = m.parse_ss(self.ss(50001, 1024 * 1024, 0) + self.ss(50002, 3 * 1024 * 1024, 0) + self.ss(50003, 2048, 0), [443])
        t.tick(100, lines, flows, {})
        with tempfile.TemporaryDirectory() as temp:
            self._db(temp, t, traffic=5 * 1024 * 1024)
            text = self._site_report(temp)
        self.assertIn('应用/网站', text); self.assertIn('YouTube', text); self.assertIn('4.0 MB', text)
        self.assertIn('rr1.googlevideo.com 等2个', text); self.assertIn('GitHub', text)
        self.assertIn('其他（无法细分）', text)
        self.assertLess(text.index('YouTube'), text.index('GitHub'))
    def test_site_report_explains_missing_logs(self):
        t = m.SiteTracker([443])
        t.status = {'sources': [], 'notes': ['Xray 关闭了访问日志（log.access 为 none），看不到访问的网站']}
        with tempfile.TemporaryDirectory() as temp:
            self._db(temp, t, traffic=900 * 1024)
            text = self._site_report(temp)
        self.assertIn('log.access 为 none', text); self.assertIn('"access"', text)
        with tempfile.TemporaryDirectory() as temp:
            self._db(temp, None, traffic=900 * 1024)
            self.assertIn('还没有记录', self._site_report(temp))
    def test_report_numbers_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            self._db(temp, None, traffic=900 * 1024)
            out = io.StringIO()
            with patch.object(m, 'DATA', Path(temp)), contextlib.redirect_stdout(out):
                m.report({'ports': [443], 'geo': True})
        self.assertRegex(out.getvalue(), r'│ #  │ IP')
        self.assertRegex(out.getvalue(), r'│ 1  │ 8\.8\.8\.8')
    def test_last_online_is_last_site_opened(self):
        # v1.0.19：最后上网 = 打开网站时间和最后一个数据包时间里更晚的（长连接在用也会更新）
        t = m.SiteTracker([443]); now = m.time.time()
        t.tick(now - 7200, [self.XRAY], m.parse_ss(self.ss(50001, 1000, 0), [443]), {})
        t.tick(now - 60, [], m.parse_ss(self.ss(50001, 900 * 1024, 0), [443]), {})
        with tempfile.TemporaryDirectory() as temp:
            db = m.open_db(Path(temp) / 'history-v1.db')
            m.save_sample(db, {('up4', '8.8.8.8'): (900 * 1024, None), ('up4', '1.1.1.1'): (900 * 1024, None)}, now)
            m.save_sites(db, t, now); db.commit(); db.close()
            out = io.StringIO()
            with patch.object(m, 'DATA', Path(temp)), contextlib.redirect_stdout(out):
                m.report({'ports': [443], 'geo': True})
            text = out.getvalue()
            opened = m.datetime.fromtimestamp(now - 7200, m.Z).strftime('%Y-%m-%d %H:%M:%S')
            self.assertIn('最后上网', text)
            last = m.datetime.fromtimestamp(now, m.Z).strftime('%Y-%m-%d %H:%M:%S')
            self.assertRegex(text, r'8\.8\.8\.8 .*' + last + r' +│')        # 取更晚的数据包时间
            self.assertRegex(text, r'1\.1\.1\.1 .*\* │')                 # 没有网站记录：退回并标 *
            self.assertIn(opened, self._site_report(temp))
    def test_site_sources_reads_proxy_configs(self):
        with tempfile.TemporaryDirectory() as temp:
            def conf(name, log):
                path = Path(temp) / name
                path.write_text('// comment\n' + json.dumps({'log': log, 'inbounds': []}))
                return str(path)
            procs = [('1', 'xray', ['/usr/local/bin/xray', 'run', '-c', conf('a.json', {'access': 'access.log'})]),
                     ('2', 'xray', ['xray', '-config=' + conf('b.json', {'access': 'none'})]),
                     ('3', 'sing-box', ['sing-box', 'run', '-c', conf('c.json', {'level': 'warn'})]),
                     ('4', 'sing-box', ['sing-box', 'run', '-c', conf('d.json', {})])]
            with patch.object(m, 'proxy_processes', return_value=procs), \
                 patch.object(m.os, 'readlink', return_value='/opt/x'), \
                 patch.object(m, 'output_target', return_value='socket:[123]'), \
                 patch.object(m, 'docker_log', return_value=None), \
                 patch.object(m, 'panel_name', return_value=None), \
                 patch.object(m, 'systemd_running', return_value=True), \
                 patch.object(m, 'service_unit', return_value='sing-box.service'), \
                 patch.object(m.shutil, 'which', return_value='/bin/journalctl'):
                sources, notes = m.site_sources(['/extra.log'])
        self.assertEqual(sources, [('file', '/extra.log'), ('file', '/opt/x/access.log'), ('journal', 'sing-box.service')])
        self.assertEqual(len(notes), 2)
        self.assertIn('none', notes[0]); self.assertIn('warn', notes[1])
    def _where(self, out='', docker=None, panel=None, systemd=False, log=None):
        with tempfile.TemporaryDirectory() as temp:
            cfg = Path(temp) / 'config.json'
            cfg.write_text(json.dumps({'log': log or {'loglevel': 'warning'}}))
            with patch.object(m.os, 'readlink', return_value=temp), \
                 patch.object(m, 'output_target', return_value=out), \
                 patch.object(m, 'docker_log', return_value=docker), \
                 patch.object(m, 'panel_name', return_value=panel), \
                 patch.object(m, 'systemd_running', return_value=systemd), \
                 patch.object(m, 'service_unit', return_value='xray.service' if systemd else None), \
                 patch.object(m.shutil, 'which', return_value='/bin/journalctl'):
                return m.proxy_log('1', 'xray', ['xray', 'run', '-c', str(cfg)])[:2]
    def test_proxy_log_finds_stdout_everywhere(self):
        # 截图里的情况：配置没写日志文件、没有 systemd（Alpine / nohup / screen 启动）
        source, note = self._where(out='pipe:[1]')
        self.assertIsNone(source); self.assertIn('没有把访问记录保存下来', note)
        self.assertTrue(m.can_enable([], [note]))
        with tempfile.NamedTemporaryFile() as f:   # OpenRC output_log / nohup.out：终端输出写进了文件
            self.assertEqual(self._where(out=f.name)[0], ('file', f.name))
        self.assertIn('/dev/null', self._where(out='/dev/null')[1])
        self.assertEqual(self._where(out='pipe:[1]', docker='/d.log')[0], ('file', '/d.log'))
        self.assertEqual(self._where(out='socket:[1]', systemd=True)[0], ('journal', 'xray.service'))
        source, note = self._where(out='pipe:[1]', panel='x-ui')
        self.assertIsNone(source); self.assertIn('面板', note); self.assertFalse(m.can_enable([], [note]))
        self.assertEqual(self._where(log={'access': '/var/log/xray/a.log'})[0], ('file', '/var/log/xray/a.log'))
    def test_enable_log_edits_config_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = Path(temp) / 'config.json'
            cfg.write_text(json.dumps({'log': {'loglevel': 'warning', 'access': 'none'}, 'inbounds': [1]}))
            procs = [('1', 'xray', ['xray', 'run', '-c', str(cfg)])]
            common = [patch.object(m, 'proxy_processes', return_value=procs),
                      patch.object(m.os, 'geteuid', return_value=0),
                      patch.object(m.os, 'readlink', return_value=temp),
                      patch.object(m.os, 'chown'),
                      patch.object(m, 'panel_name', return_value=None),
                      patch.object(m, 'proc_status', return_value={'Uid': '65534 65534 65534 65534'}),
                      patch.object(m, 'ACCESS_DIR', Path(temp) / 'acc'),
                      patch.object(m, 'ACCESS_LOG', Path(temp) / 'acc' / 'access.log'),
                      patch.object(m, 'systemd_running', return_value=False),
                      patch.object(m.subprocess, 'run')]
            with contextlib.ExitStack() as stack:
                for c in common: stack.enter_context(c)
                stack.enter_context(patch.object(m, 'check_config', return_value=(False, 'bad')))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                m.enable_log(assume_yes=True)
            self.assertEqual(json.loads(cfg.read_text())['log']['access'], 'none')   # 自检不过：还原
            out = io.StringIO()
            with contextlib.ExitStack() as stack:
                for c in common: stack.enter_context(c)
                stack.enter_context(patch.object(m, 'check_config', return_value=(True, '')))
                stack.enter_context(patch.object(m, 'restart_proxy', return_value=None))
                stack.enter_context(contextlib.redirect_stdout(out))
                m.enable_log(assume_yes=True)
            data = json.loads(cfg.read_text())
            self.assertEqual(data['log'], {'loglevel': 'warning', 'access': str(Path(temp) / 'acc' / 'access.log')})
            self.assertEqual(data['inbounds'], [1])
            self.assertIn('已打开', out.getvalue())
            self.assertEqual(len(list(Path(temp).glob('config.json.liuliang-bak-*'))), 1)
    def test_enabled_log_is_trimmed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'access.log'; path.write_text('')
            with patch.object(m, 'ACCESS_LOG', path), patch.object(m, 'ACCESS_MAX', 10):
                f = m.FileFollower(str(path))
                with open(path, 'a') as h: h.write('a line longer than ten\n')
                self.assertEqual(f.lines(), ['a line longer than ten'])
                self.assertEqual(path.stat().st_size, 0)
                with open(path, 'a') as h: h.write('next\n')
                self.assertEqual(f.lines(), ['next'])
                f.close()
    def test_file_follower_handles_rotation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'access.log'
            path.write_text('old line\n')
            f = m.FileFollower(str(path))
            with open(path, 'a') as h: h.write('new 1\npart')
            self.assertEqual(f.lines(), ['new 1'])
            with open(path, 'a') as h: h.write('ial\n')
            self.assertEqual(f.lines(), ['partial'])
            path.rename(Path(temp) / 'access.log.1'); path.write_text('after rotate\n')
            self.assertEqual(f.lines(), ['after rotate'])
            f.close()
    def test_sites_are_kept_eight_days(self):
        db = m.open_db(':memory:')
        t = m.SiteTracker([443]); t.tick(100, [self.XRAY], {}, {})
        # 还没找过日志：不写状态，报表不会误说「读不到」
        m.save_sites(db, m.SiteTracker([443]), 900)
        self.assertIsNone(db.execute("select value from metadata where key='sites'").fetchone())
        m.save_sites(db, t, 1000)
        t.tick(100, [self.XRAY], {}, {})
        m.save_sites(db, t, 1000 + 8 * 86400 + 1)
        self.assertEqual(db.execute('select count(*) from sites').fetchone()[0], 1)
        db.close()


class V119Tests(unittest.TestCase):
    def test_default_shows_small_node_traffic(self):
        with tempfile.TemporaryDirectory() as temp:
            now=m.time.time(); db=m.open_db(Path(temp)/'history-v1.db')
            m.save_sample(db,{('up4','5.5.5.5'):(9158, None)},now); db.close()
            out=io.StringIO()
            with patch.object(m,'DATA',Path(temp)),contextlib.redirect_stdout(out):m.report({'ports':[443],'geo':True})
            self.assertIn('5.5.5.5',out.getvalue())
    def test_last_seen_follows_long_connection(self):
        with tempfile.TemporaryDirectory() as temp:
            db=m.open_db(Path(temp)/'h.db'); t0=1_000_000.0
            for i in range(5):
                m.save_sample(db,{('up4','6.6.6.6'):(1000*(i+1), m.SET_TIMEOUT-3)},t0+60*i)
            ls=db.execute("select last_seen from clients where ip='6.6.6.6'").fetchone()[0]
            self.assertAlmostEqual(ls, t0+240-3, delta=1)
            self.assertEqual(db.execute("select sum(bytes) from traffic").fetchone()[0],5000)
    def test_interval_at_most_60(self):
        self.assertLessEqual(m.INTERVAL,60)
    def test_install_embeds_same_program(self):
        s=Path(__file__).with_name('install.sh').read_text()
        a=s.index("<<'LIULIANG_PYTHON'\n")+len("<<'LIULIANG_PYTHON'\n"); b=s.index("\nLIULIANG_PYTHON\n")
        self.assertEqual(s[a:b], Path(__file__).with_name('liuliang.py').read_text().rstrip('\n'))

class V120Tests(unittest.TestCase):
    def test_log_choice(self):
        self.assertEqual(m.auto_log_choice(None, {}, 512), 'yes')
        self.assertEqual(m.auto_log_choice(None, {}, 32), 'no')
        self.assertEqual(m.auto_log_choice(None, {'log':'no'}, 512), 'no')   # 保留用户选择
        self.assertEqual(m.auto_log_choice('yes', {'log':'no'}, 32), 'yes')  # 命令行最优先
        self.assertEqual(m.auto_log_choice(None, {}, 0), 'yes')              # 读不到内存按默认
    def test_access_cap(self):
        self.assertEqual(m.access_cap(64), m.ACCESS_MAX_SMALL)
        self.assertEqual(m.access_cap(1024), m.ACCESS_MAX)
    NETDEV = 'Inter-|   Receive\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n    lo: 5 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 3000 20 0 0 0 0 0 0\n'
    def test_nic_bytes(self):
        self.assertEqual(m.nic_bytes('eth0', self.NETDEV), (1000, 3000))
        self.assertIsNone(m.nic_bytes('eth9', self.NETDEV))
    def _nicdb(self, temp):
        db=m.open_db(Path(temp)/'history-v1.db'); now=m.time.time()
        m.save_nic(db, now-300, 'eth0', (1000, 3000))      # 第一次只记基线
        m.save_nic(db, now-200, 'eth0', (3000, 4000))      # +2000 收 +1000 发
        m.save_nic(db, now-100, 'eth0', (500, 200))        # 重启归零：从 0 算起
        m.save_sample(db,{('up4','5.5.5.5'):(9158, None)},now); db.commit(); db.close()
    def test_nic_reset_and_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            self._nicdb(temp)
            db=sqlite3.connect(str(Path(temp)/'history-v1.db'))
            rx,tx=m.nic_usage(db,0,m.time.time()+1)
            self.assertEqual((rx,tx),(2500,1200))
            self.assertEqual(m.billing_figure('both',rx,tx),3700)
            self.assertEqual(m.billing_figure('out',rx,tx),1200)
            self.assertEqual(m.billing_figure('max',rx,tx),2500)
    def _report(self, temp, cfg):
        out=io.StringIO()
        with patch.object(m,'DATA',Path(temp)),contextlib.redirect_stdout(out):m.report(dict({'ports':[443],'geo':True},**cfg))
        return out.getvalue()
    def test_report_billing_default_both(self):
        with tempfile.TemporaryDirectory() as temp:
            self._nicdb(temp); text=self._report(temp,{})
            self.assertIn('服务商口径（进+出）',text); self.assertIn('3.6 KB',text); self.assertIn('SSH',text)
    def test_report_billing_all(self):
        with tempfile.TemporaryDirectory() as temp:
            self._nicdb(temp); text=self._report(temp,{'billing':'all'})
            self.assertIn('出站',text); self.assertIn('取大',text); self.assertIn('对得上的那个',text)
    def test_report_billing_out(self):
        with tempfile.TemporaryDirectory() as temp:
            self._nicdb(temp); text=self._report(temp,{'billing':'out'})
            self.assertIn('服务商口径（出站）',text); self.assertNotIn('取大',text)

if __name__=='__main__':unittest.main(verbosity=2)
