import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
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
    def test_nft_check_fails_fast_with_friendly_error(self):
        # 容器型 VPS 没给 nftables 权限时，安装应在动任何东西之前就报错，
        # 而不是装到一半崩掉。
        def fake(args, **kwargs):
            raise m.subprocess.CalledProcessError(
                1, args,
                stderr='netlink: Error: cache initialization failed: Operation not permitted')
        with patch.object(m, 'run', side_effect=fake):
            with self.assertRaises(RuntimeError) as ctx:
                m.check_nft_or_die('table inet liuliang_v1 { }')
        message = str(ctx.exception)
        self.assertIn('nftables', message)
        self.assertIn('KVM', message)
    def test_nft_check_passes_when_usable(self):
        with patch.object(m, 'run') as run:
            run.return_value.stdout = ''
            m.check_nft_or_die('table inet liuliang_v1 { }')  # 不抛异常就算过
    def test_payload_is_self_contained(self):
        s=Path(__file__).with_name('install.sh').read_text()
        payload=s.split("<<'LIULIANG_PYTHON'\n",1)[1].split('\nLIULIANG_PYTHON\n',1)[0]+'\n'
        self.assertEqual(payload,Path(__file__).with_name('liuliang.py').read_text())

if __name__=='__main__':unittest.main(verbosity=2)
