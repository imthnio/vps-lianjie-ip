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
            with patch.object(m,'DATA',Path(temp)),contextlib.redirect_stdout(out):m.report({'ports':[443],'geo':True})
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
    def test_payload_is_self_contained(self):
        s=Path(__file__).with_name('install.sh').read_text()
        payload=s.split("<<'LIULIANG_PYTHON'\n",1)[1].split('\nLIULIANG_PYTHON\n',1)[0]+'\n'
        self.assertEqual(payload,Path(__file__).with_name('liuliang.py').read_text())

if __name__=='__main__':unittest.main(verbosity=2)
