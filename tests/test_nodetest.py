import contextlib
from collections import Counter
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import nodetest as n

SOURCE = '''external-controller: ":9090"
secret: 'synthetic-controller-token'
proxies:
  - {name: TestNode, type: http, server: node.example.invalid, port: 443, password: synthetic-password}
  - {name: OtherNode, type: socks5, server: 192.0.2.9, port: 8443, password: other-password}
proxy-providers: {}
'''


def sample(code=200, ms=100, size=1024, exitcode=0, connects=1):
    return dict(http_code=code, appconnect_ms=20, ttfb_ms=ms, total_ms=1000,
                bytes=size, exitcode=exitcode, connects=connects, note=n.curl_reason(exitcode))


def row(node='A', target='web', kind='cold', code=200, ms=100, phase='latency', mbps=None):
    return dict(sample(code, ms), node=node, target=target, kind=kind,
                phase=phase, mbps=mbps, time='2026-01-01T00:00:00', round=1, node_type='Http')


def fake_socket_factory():
    """No sockets even on hosts whose sandbox permits local networking."""
    counter = iter(range(40000, 41000))
    def create():
        sock = mock.Mock()
        port = next(counter)
        sock.getsockname.return_value = ('127.0.0.1', port)
        return sock
    return create


class URLTests(unittest.TestCase):
    def test_forbidden_hosts_and_invalid_urls(self):
        for url in ('https://claude.ai', 'https://api.anthropic.com/',
                    'https://notCLAUDE.example.org/', 'https://ANTHROPIC.invalid',
                    'file:///tmp/test', 'https://user:pass@example.org', 'https://example.org:bad',
                    'https://example.org/\n', 'https://cl%61ude.ai'):
            with self.subTest(url=url):
                with self.assertRaises(n.UserError):
                    n.validate_url(url)
        self.assertEqual(n.validate_url('https://example.org/claude'), 'https://example.org/claude')
        for url in ('https://\uff43\uff4c\uff41\uff55\uff44\uff45.ai/', 'https://clau\u00adde.ai/', 'https://b\u00fccher.example/',
                    'https://{cl,o}aude.ai/', 'https://[cl-c]aude.ai/', 'https://cl*ude.ai/'):
            with self.subTest(url=url):
                with self.assertRaises(n.UserError):
                    n.validate_url(url)
        self.assertIn('--globoff', n.curl_args(1080, 5))
        self.assertEqual(n.validate_url('https://my_host.example/'), 'https://my_host.example/')

    def test_rejected_before_config_access(self):
        with mock.patch.object(n, 'find_config', side_effect=AssertionError('must not read')):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(n.main(['--target', 'bad=https://claude.ai']), 1)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(n.socket, 'socket', side_effect=fake_socket_factory())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_controller_scan(self):
        self.assertEqual(n.read_controller(SOURCE), (':9090', 'synthetic-controller-token'))
        for value in (':9090', '0.0.0.0:9090', '127.0.0.1:9090', 'http://localhost:9090'):
            base, secret = n.read_controller('external-controller: "' + value + '"\nsecret: "a#b" # c\n')
            self.assertIn(n.normalize_controller(base), ('http://127.0.0.1:9090', 'http://localhost:9090'))
            self.assertEqual(secret, 'a#b')
        # An unusable configured address must not block an explicit override.
        self.assertEqual(n.read_controller('external-controller: "[::]:9090"\n')[0], '[::]:9090')
        self.assertEqual(n.read_controller("secret: 'a''b' # comment\n"), (None, "a'b"))
        self.assertEqual(n.read_controller('secret: abc # comment\n')[1], 'abc')
        for value in ('192.0.2.1:9090', 'https://127.0.0.1:9090', '127.0.0.1:9090/proxies'):
            with self.assertRaises(n.UserError):
                n.normalize_controller(value)

    def test_environment(self):
        self.assertEqual(n.clean_env({'HTTP_PROXY': 'bad', 'https_proxy': 'bad', 'ALL_PROXY': 'bad',
                                      'NO_PROXY': '*', 'no_proxy': '*', 'PATH': 'ok'}), {'PATH': 'ok'})

    def test_private_files(self):
        locations = []
        try:
            for _ in range(2):
                directory, config, sockets = n.private_files(SOURCE)
                locations.append((directory, sockets))
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                for name in ('src.yaml', 'config.yaml'):
                    self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o600)
                self.assertEqual((directory / 'src.yaml').read_text(), SOURCE)
                self.assertEqual(config['proxy-providers']['src']['path'], './src.yaml')
                ports = [listener['port'] for listener in config['listeners']]
                ports.append(int(config['external-controller'].rsplit(':', 1)[1]))
                self.assertEqual(len(set(ports)), 5)
                self.assertNotIn('mixed-port', config)
                self.assertEqual(config['rules'], ['MATCH,REJECT'])
                self.assertEqual(config['bind-address'], '127.0.0.1')
                self.assertFalse(config['allow-lan'])
                self.assertFalse(config['profile']['store-selected'])
                self.assertGreaterEqual(len(config['secret']), 32)
            configs = [json.loads((directory / 'config.yaml').read_text()) for directory, _ in locations]
            self.assertNotEqual(configs[0]['secret'], configs[1]['secret'])
            self.assertNotEqual(configs[0]['listeners'][0]['port'], configs[1]['listeners'][0]['port'])
        finally:
            for directory, sockets in locations:
                core = n.PrivateCore('unused', '')
                core.directory, core.sockets = directory, sockets
                core.close()
                self.assertFalse(directory.exists())

    def test_listener_counts_and_bindings(self):
        for jobs in (1, 4, 8):
            core = n.PrivateCore('unused', '', jobs)
            try:
                core.directory, config, core.sockets = n.private_files(SOURCE, jobs)
                groups = config['proxy-groups']
                listeners = config['listeners']
                self.assertEqual([group['name'] for group in groups], ['T%d' % i for i in range(1, jobs + 1)])
                self.assertEqual(len(listeners), jobs)
                for group, listener in zip(groups, listeners):
                    self.assertEqual(group['use'], ['src'])
                    self.assertEqual(listener['proxy'], group['name'])
                    self.assertEqual(listener['listen'], '127.0.0.1')
                    self.assertEqual(listener['type'], 'mixed')
                ports = [listener['port'] for listener in listeners] + [int(config['external-controller'].rsplit(':', 1)[1])]
                self.assertEqual(len(set(ports)), jobs + 1)
                self.assertEqual(config['rules'], ['MATCH,REJECT'])
                self.assertNotIn('mixed-port', config)
                self.assertNotIn('port', config)
                self.assertNotIn('socks-port', config)
            finally:
                core.close()

    def test_cleanup_stops_owned_process(self):
        core = n.PrivateCore('unused', '')
        core.directory, _, core.sockets = n.private_files(SOURCE)
        directory = core.directory
        core.process = mock.Mock()
        core.process.poll.return_value = None
        core.process.wait.side_effect = [subprocess.TimeoutExpired('fake', 3), 0]
        core.close()
        core.process.terminate.assert_called_once()
        core.process.kill.assert_called_once()
        self.assertFalse(directory.exists())

    def test_signal_during_cleanup_still_removes_directory(self):
        core = n.PrivateCore('unused', '')
        core.directory, _, core.sockets = n.private_files(SOURCE)
        directory = core.directory
        real_rmtree = n.shutil.rmtree

        def rmtree_with_signal(path):
            os.kill(os.getpid(), signal.SIGTERM)
            real_rmtree(path)

        def handler(signum, frame):
            raise n.Interrupted()

        old = signal.signal(signal.SIGTERM, handler)
        try:
            with mock.patch.object(n.shutil, 'rmtree', side_effect=rmtree_with_signal):
                with self.assertRaises(n.Interrupted):
                    core.close()
        finally:
            signal.signal(signal.SIGTERM, old)
        self.assertFalse(directory.exists())

    def test_start_failure_is_clean_and_does_not_emit_log(self):
        core = n.PrivateCore('fake', SOURCE)
        process = mock.Mock()
        process.poll.return_value = 1
        with mock.patch.object(n.subprocess, 'Popen', return_value=process):
            with self.assertRaises(n.UserError) as caught:
                core.__enter__()
        self.assertFalse(core.directory.exists())
        for value in n.sensitive_values(SOURCE):
            self.assertNotIn(value, str(caught.exception))

    def test_skip_members_and_snapshots(self):
        proxies = {'G': {'type': 'URLTest', 'now': 'A'}, 'A': {'type': 'Tuic'},
                   'D': {'type': 'Direct'}, 'R': {'type': 'Reject'}}
        self.assertEqual(n.group_nodes(proxies, ['G', 'A', 'D', 'R', 'missing', 'A']),
                         ([('A', 'Tuic')], ['G', 'D', 'R', 'missing']))
        self.assertEqual(n.selections(proxies), {'G': 'A'})

    def test_client_is_read_only_and_private_put(self):
        self.assertFalse(hasattr(n.ReadController, 'put'))
        core = n.PrivateCore('unused', '')
        core.config = {'secret': 'private-token'}
        core.api = n.ReadController('127.0.0.1:45678', 'private-token')
        core.group_apis = {'T1': core.api, 'T2': core.api}
        response = mock.MagicMock()
        response.__enter__.return_value.status = 204
        with mock.patch.object(core.api.opener, 'open', return_value=response) as call:
            core.select('TestNode', 'T2')
        request = call.call_args[0][0]
        self.assertEqual(request.full_url, 'http://127.0.0.1:45678/proxies/T2')
        self.assertEqual(request.method, 'PUT')
        self.assertEqual(json.loads(request.data), {'name': 'TestNode'})


class CurlTests(unittest.TestCase):
    def test_dependency_version(self):
        with mock.patch.object(n.shutil, 'which', return_value=None):
            with self.assertRaises(n.UserError):
                n.check_curl()
        for version in ('8.5.0', '8.4.0', '7.88.1'):
            with mock.patch.object(n.shutil, 'which', return_value='/fake/curl'), \
                 mock.patch.object(n.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'curl ' + version)):
                if version == '8.5.0':
                    n.check_curl()
                else:
                    with self.assertRaises(n.UserError):
                        n.check_curl()

    def test_parse_two_and_failure(self):
        parsed = n.parse_curl('\nNODETEST\t204\t0.12\t0.15\t0.2\t0\t0\t1\n'
                              '\nNODETEST\t000\t0\t0\t2\t0\t28\t0\n')
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]['appconnect_ms'], 120)
        self.assertEqual(parsed[0]['ttfb_ms'], 150)
        self.assertEqual(parsed[1]['http_code'], 0)
        self.assertIn('超时', parsed[1]['note'])

    def test_partial_download_timeout(self):
        parsed = n.parse_curl('NODETEST\t200\t0.1\t1\t5\t1048576\t28\t1\n')[0]
        self.assertAlmostEqual(n.bandwidth(parsed), 1048576 * 8 / 4 / 1e6)
        for changes in ({'http_code': 403}, {'bytes': 100}, {'exitcode': 56}, {'ttfb_ms': 5000}):
            with self.subTest(changes=changes):
                self.assertIsNone(n.bandwidth(dict(parsed, **changes)))

    def test_command_reuses_one_process_and_no_environment_proxy(self):
        output = ('NODETEST\t200\t0.1\t0.2\t0.3\t10\t0\t1\n'
                  'NODETEST\t200\t0\t0.1\t0.2\t10\t0\t0\n')
        with mock.patch.dict(os.environ, {'HTTP_PROXY': 'invalid', 'NO_PROXY': '*'}):
            with mock.patch.object(n.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output)) as call:
                results = n.curl_measure(54321, 'https://example.org/', 2, twice=True)
        call.assert_called_once()
        command = call.call_args[0][0]
        self.assertEqual(command[:2], ['curl', '-q'])
        self.assertEqual(command.count('https://example.org/'), 2)
        self.assertNotIn('--location', command)
        self.assertEqual(command[command.index('--noproxy') + 1], '')
        self.assertNotIn('HTTP_PROXY', call.call_args[1]['env'])
        self.assertNotIn('NO_PROXY', call.call_args[1]['env'])
        self.assertEqual(results[1]['connects'], 0)

    def test_bandwidth_limits(self):
        output = 'NODETEST\t200\t0.1\t1\t5\t1048576\t28\t1\n'
        with mock.patch.object(n.subprocess, 'run', return_value=subprocess.CompletedProcess([], 28, output)) as call:
            n.curl_measure(12345, n.BW_URL.format(8388608), 5, max_bytes=8388608, limit_rate='2M')
        command = call.call_args[0][0]
        for option, value in (('--max-time', '5'), ('--max-filesize', '8388608'), ('--limit-rate', '2M')):
            self.assertEqual(command[command.index(option) + 1], value)

    def test_bad_output_and_process_timeout(self):
        for output in ('NODETEST\tbad', 'NODETEST\t200\tnan\t0\t0\t0\t0\t0'):
            with self.assertRaises(n.UserError):
                n.parse_curl(output)
        with mock.patch.object(n.subprocess, 'run', side_effect=subprocess.TimeoutExpired('curl', 2)):
            results = n.curl_measure(12345, 'https://example.org/', 1, twice=True)
        self.assertEqual([item['http_code'] for item in results], [0, 0])


class RankingTests(unittest.TestCase):
    def test_region_names_are_unified(self):
        expected = {'US': '美国', 'JP': '日本', 'SG': '新加坡', 'HK': '香港', 'TW': '台湾',
                    'KR': '韩国', 'GB': '英国', 'FR': '法国', 'DE': '德国', 'NL': '荷兰',
                    'CA': '加拿大', 'AU': '澳大利亚', 'IN': '印度', 'MY': '马来西亚',
                    'TH': '泰国', 'ID': '印尼', 'VN': '越南', 'PH': '菲律宾', 'TR': '土耳其', 'RU': '俄罗斯'}
        for code, chinese in expected.items():
            self.assertEqual(n.region_name('node', code), chinese)
            self.assertEqual(n.region_name(chinese + '02'), chinese)
        self.assertEqual(n.region_name('node', 'ZZ'), 'ZZ')
        nodes = [('日本01', 'Http'), ('日本02', 'Http')]
        rows = [row(name, kind=kind) for name, _ in nodes for kind in ('cold', 'warm')]
        ranked = n.rank_nodes(nodes, rows, ['web'], 10, True, {'日本01': 'JP'})
        self.assertEqual([item['region'] for item in ranked], ['日本', '日本'])
        summary = n.make_summary(ranked, ['web'], [], {}, {}, True, 10)
        best = next(line for line in summary.splitlines() if line.startswith('各地区最佳'))
        self.assertEqual(best.count('日本='), 1)
        self.assertNotIn('JP=', best)
        self.assertTrue(all(line == line.rstrip() for line in summary.splitlines()))

    def test_elimination_and_bandwidth_priority(self):
        nodes = [(name, 'Http') for name in 'ABCDE']
        rows = []
        for name in 'ABCDE':
            rows += [row(name, kind=kind, ms=10 if name == 'A' else 100) for kind in ('cold', 'warm') for _ in range(5)]
        rows += [row('A', phase='bw1', kind='bw', mbps=5), row('B', phase='bw2', kind='bw', mbps=15)]
        for item in rows:
            if item['node'] == 'C':
                item['http_code'] = 0
        rows += [row('D', target='other', code=0)]
        rows += [row(name, target='other') for name in 'ABCE']
        ranked = n.rank_nodes(nodes, rows, ['web', 'other'], 10)
        self.assertEqual(ranked[0]['node'], 'B')
        by_name = {item['node']: item for item in ranked}
        self.assertTrue(by_name['C']['reasons'])
        self.assertIn('other全失败', by_name['D']['reasons'])
        self.assertFalse(by_name['E']['reasons'])
        self.assertEqual(n.rank_nodes(nodes, rows, ['web', 'other'], 10, quick=True)[0]['node'], 'A')
        # A deep-test result overrides a faster screening result.
        rows += [row('E', phase='bw1', kind='bw', mbps=20), row('E', phase='bw2', kind='bw', mbps=7)]
        by_name = {item['node']: item for item in n.rank_nodes(nodes, rows, ['web', 'other'], 10)}
        self.assertEqual(by_name['E']['mbps'], 7)
        self.assertFalse(by_name['E']['qualified'])

    def test_twenty_percent_is_allowed_and_http_errors_succeed(self):
        rows = [row(code=403) for _ in range(4)] + [row(code=0)]
        ranked = n.rank_nodes([('A', 'Http')], rows, ['web'], 10, quick=True)
        self.assertFalse(ranked[0]['reasons'])
        self.assertEqual(ranked[0]['failure_rate'], 0.2)
        rows.append(row(code=0))
        self.assertIn('失败率>20%', n.rank_nodes([('A', 'Http')], rows, ['web'], 10)[0]['reasons'])

    def test_summary_no_unqualified_recommendation(self):
        ranked = n.rank_nodes([('A', 'Http')], [row(), row(kind='warm')], ['web'], 10)
        summary = n.make_summary(ranked, ['web'], ['DIRECT'], {'G': 'A'}, {'G': 'B'}, False, 10)
        self.assertIn('无；本次没有', summary)
        self.assertIn('发生变化', summary)
        self.assertIn('本工具未切换客户端', summary)


class OutputTests(unittest.TestCase):
    def test_redaction(self):
        sensitive = n.sensitive_values(SOURCE)
        text = 'node.example.invalid 192.0.2.9 2001:db8::1 synthetic-password synthetic-controller-token other-password'
        scrubbed = n.redact(text, sensitive)
        for value in text.split():
            self.assertNotIn(value, scrubbed)
        self.assertNotIn('123e4567-e89b-12d3-a456-426614174000', n.redact('123e4567-e89b-12d3-a456-426614174000'))

    def test_short_and_numeric_credentials_are_redacted(self):
        source = "proxies:\n  - {name: node-12345678, type: http, server: h.example.invalid, port: 443, password: '12345678'}\n  - {name: x-abc12, type: socks5, server: 192.0.2.4, port: 1080, username: abc12, password: abc12}\n"
        sensitive = n.sensitive_values(source)
        self.assertNotIn('12345678', n.redact('node-12345678', sensitive))
        self.assertNotIn('abc12', n.redact('x-abc12', sensitive))
        self.assertNotIn('443', sensitive)
        self.assertNotIn('-', n.sensitive_values('dns:\n  nameserver: -\n  proxy-server-nameserver: -\n'))

    def test_yaml_scalar_forms_and_unparsed_flag(self):
        for raw in ('"\\x61bc12"', '&pass abc12', '!!str abc12', "'abc12'", 'abc12 # c'):
            self.assertEqual(n.scalar(raw), 'abc12')
        values, unparsed = n.credential_scan("proxies:\n  - name: a\n    password: >-\n      abc12\n")
        self.assertTrue(unparsed)
        self.assertFalse(n.credential_scan(SOURCE)[1])
        # An unparseable configured secret must leave room for --secret.
        self.assertEqual(n.read_controller('external-controller: "\\q"\nsecret: "\\x61bc12"\n'), (None, 'abc12'))

    def test_duplicate_short_values_do_not_expand(self):
        source = 'proxies:\n' + ''.join('  - {name: n%d, type: http, username: e, password: abcd}\n' % i for i in range(23))
        self.assertEqual(n.redact('google', n.sensitive_values(source)), 'google')
        self.assertEqual(n.redact('US abcd abcd', n.sensitive_values(source)), 'US [redacted] [redacted]')

    def test_redaction_keeps_node_names(self):
        sensitive = n.sensitive_values('port: 0\nsocks-port: 7891\n' + SOURCE)
        self.assertNotIn('0', sensitive)
        self.assertNotIn('443', sensitive)
        for name in ('🇭🇰 香港02', '新加坡07', '美国 1.5倍', 'v2 日本 0.8x', '美国ISP'):
            self.assertEqual(n.redact(name, sensitive), name)
        self.assertNotIn('198.51.100.7', n.redact('via 198.51.100.7', sensitive))

    def test_filename_and_cjk(self):
        for value in ('../../bad/name', 'a:b\\c\n', '', '  ..', '标签 /school'):
            name = n.safe_name(value)
            self.assertNotIn('/', name)
            self.assertNotIn('\\', name)
            self.assertNotIn('\n', name)
            self.assertFalse(name.startswith('.'))
        self.assertEqual(n.width('日本a'), 5)
        self.assertEqual(n.width(n.pad('日本', 7)), 7)
        self.assertEqual(n.display_name('🇯🇵 日本'), '日本')

    def test_csv_privacy_and_no_overwrite(self):
        public = lambda text: n.redact(text, n.sensitive_values(SOURCE))
        rows = [dict(row(node=public('TestNode')), note=public('node.example.invalid synthetic-password'))]
        with tempfile.TemporaryDirectory() as directory:
            first = n.write_results(directory, 'test-host', '../../school', 'group', rows, 'summary')
            second = n.write_results(directory, 'test-host', '../../school', 'group', rows, 'summary')
            self.assertNotEqual(first, second)
            raw = first[1].read_bytes()
            self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
            for value in ('node.example.invalid', 'synthetic-password', 'synthetic-controller-token', '192.0.2.9'):
                self.assertNotIn(value, raw.decode('utf-8-sig'))
            self.assertIn('appconnect_ms', raw.decode('utf-8-sig'))

    def test_cmd_is_ascii_crlf(self):
        data = Path('nodetest.cmd').read_bytes()
        data.decode('ascii')
        self.assertNotIn(b'\n', data.replace(b'\r\n', b''))
        self.assertIn(b'%*', data)
        self.assertIn(b'NODETEST_DISTRO', data)


class GeminiTests(unittest.TestCase):
    def test_verdict_markers(self):
        self.assertEqual(n.gemini_verdict('x,\\"45631641\\":false,y ,2,1,200,"SGP"'), ('不可用', 'SGP', ''))
        self.assertEqual(n.gemini_verdict('{"45631641":true}'), ('可用', '', ''))
        self.assertEqual(n.gemini_verdict('[45631641,null,true] ,2,1,200,"USA"'), ('可用', 'USA', ''))
        self.assertEqual(n.gemini_verdict('<html>changed</html>'), ('未知', '', ''))
        for body in ('[145631641,null,true]', '[45631641,null,trueValue]', '{"45631641":falsehood}', '{"x45631641":true}'):
            self.assertEqual(n.gemini_verdict(body)[0], '未知', body)
        consent = '"https://consent.google.com/save?continue" \\"45631641\\":false ,2,1,200,"FRA"'
        self.assertEqual(n.gemini_verdict(consent), ('未知', 'FRA', '需同意页'))
        self.assertEqual(n.gemini_label({'status': '未知', 'country': 'FRA', 'reason': '需同意页'}), '未知(FRA·需同意页)')

    def test_check_parses_body_and_write_out(self):
        body = 'a\\"45631641\\":true ,2,1,200,"JPN"'
        tail = '\nNODETEST\t200\t0.1\t0.2\t0.3\t1000\t0\t1\n'
        for code, expected in ((200, ('可用', 'JPN')), (403, ('未知', ''))):
            done = subprocess.CompletedProcess([], 0, body + tail.replace('200', str(code), 1), None)
            with mock.patch.object(n.subprocess, 'run', return_value=done) as run:
                result = n.gemini_check(4000, 8)
            self.assertEqual((result['status'], result['country']), expected)
            command = run.call_args.args[0]
            self.assertIn('--compressed', command)
            self.assertEqual(command[-1], n.GEMINI_URL)
            self.assertEqual(run.call_args.kwargs['env'], n.clean_env())

    def test_incomplete_page_is_unknown(self):
        body = 'a\\"45631641\\":false ,2,1,200,"SGP"'
        for exitcode in (18, 28, 63):
            tail = '\nNODETEST\t200\t0.1\t0.2\t0.3\t1000\t%d\t1\n' % exitcode
            done = subprocess.CompletedProcess([], exitcode, body + tail, None)
            with mock.patch.object(n.subprocess, 'run', return_value=done):
                result = n.gemini_check(4000, 8)
            self.assertEqual(result['status'], '未知')
            self.assertEqual(result['sample']['exitcode'], exitcode)

    def test_check_timeout_is_unknown(self):
        with mock.patch.object(n.subprocess, 'run', side_effect=subprocess.TimeoutExpired('curl', 1)):
            result = n.gemini_check(4000, 8)
        self.assertEqual((result['status'], result['sample']['http_code']), ('未知', 0))

    def test_summary_flags_fast_nodes_without_gemini(self):
        rows = [row('A'), row('A', kind='warm'), row('B', ms=200), row('B', kind='warm')]
        checks = {'A': {'status': '不可用', 'country': 'SGP'}, 'B': {'status': '可用', 'country': 'USA'}}
        ranked = n.rank_nodes([('A', 'Http'), ('B', 'Http')], rows, ['web'], 10, True, {}, checks)
        text = n.make_summary(ranked, ['web'], [], {}, {}, True, 10)
        self.assertIn('建议长期固定（本次候选）：A（Gemini 不可用）、B', text)
        self.assertIn('兼顾 Gemini 的候选：B', text)
        self.assertIn('延迟合格但 Gemini 不可用：A', text)
        self.assertIn('不可用(SGP)', text)
        self.assertNotIn('Gemini', n.make_summary(n.rank_nodes([('A', 'Http')], rows, ['web'], 10, True), ['web'], [], {}, {}, True, 10))
        # Full mode only reports bandwidth-qualified nodes.
        rows += [row('A', phase='bw1', mbps=50), row('B', phase='bw1', mbps=2)]
        ranked = n.rank_nodes([('A', 'Http'), ('B', 'Http')], rows, ['web'], 10, False, {}, checks)
        text = n.make_summary(ranked, ['web'], [], {}, {}, False, 10)
        self.assertIn('建议长期固定（本次候选）：A（Gemini 不可用）\n', text)
        self.assertIn('兼顾 Gemini 的候选：无', text)
        self.assertIn('带宽达标但 Gemini 不可用：A', text)


class WorkflowTests(unittest.TestCase):
    def test_full_bandwidth_workflow_and_interleaving(self):
        names = ['TestNode', 'OtherNode', 'ThirdNode', 'FourthNode', 'FailedNode']
        proxies = {name: {'type': 'Http'} for name in names}
        proxies['AI专用'] = {'type': 'URLTest', 'now': names[0], 'all': names}
        client = mock.Mock()
        client.get.side_effect = lambda path: {'all': names} if path != '/proxies' else {'proxies': proxies}
        core = mock.MagicMock()
        core.__enter__.return_value = core
        core.available = set(names)
        core.config = {'listeners': [{'proxy': 'T1', 'port': 54321}]}
        current = ['']
        core.select.side_effect = lambda name, group='T1': current.__setitem__(0, name)
        def measure(port, url, timeout, **kwargs):
            if kwargs.get('twice'):
                return [sample(code=0 if current[0] == 'FailedNode' else 200), sample(code=0 if current[0] == 'FailedNode' else 200, connects=0)]
            return [sample(size=1024 * 1024 * (names.index(current[0]) + 1), exitcode=28)]
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'source.yaml'
            config.write_text(SOURCE)
            args = n.parser().parse_args(['--config', str(config), '--rounds', '2', '--jobs', '1', '--out', directory])
            with mock.patch.object(n, 'ReadController', return_value=client), \
                 mock.patch.object(n, 'ensure_core', return_value=Path('fake')), \
                 mock.patch.object(n, 'PrivateCore', return_value=core), \
                 mock.patch.object(n, 'check_curl'), \
                 mock.patch.object(n, 'curl_measure', side_effect=measure) as measurements, \
                 mock.patch.object(n, 'trace_location', return_value='JP'), \
                 mock.patch.object(n, 'gemini_check', return_value={'status': '不可用', 'country': 'SGP', 'sample': sample()}), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                n.run(args)
            selected = [call.args[0] for call in core.select.call_args_list]
            self.assertEqual(selected[:10], names + names[1:] + names[:1])
            self.assertNotIn('FailedNode', selected[10:])
            self.assertEqual(selected[-3:], ['FourthNode', 'ThirdNode', 'OtherNode'])
            self.assertEqual(len(selected), 17)
            bandwidth_calls = [call for call in measurements.call_args_list if not call.kwargs.get('twice')]
            self.assertEqual([call.args[2] for call in bandwidth_calls], [5] * 4 + [10] * 3)
            self.assertIn('136 MiB', output.getvalue())
            text = next(Path(directory).glob('*-raw.csv')).read_text(encoding='utf-8-sig')
            for secret in ('node.example.invalid', 'synthetic-password', 'synthetic-controller-token', '192.0.2.9'):
                self.assertNotIn(secret, text)

    def test_measurement_error_cleans_core_and_takes_end_snapshot(self):
        proxies = {'AI专用': {'type': 'Selector', 'now': 'TestNode', 'all': ['TestNode']}, 'TestNode': {'type': 'Http'}}
        client = mock.Mock()
        client.get.side_effect = lambda path: {'all': ['TestNode']} if path != '/proxies' else {'proxies': proxies}
        core = mock.MagicMock()
        core.__enter__.return_value = core
        core.available = {'TestNode'}
        core.config = {'listeners': [{'proxy': 'T1', 'port': 54321}]}
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'source.yaml'
            config.write_text(SOURCE)
            args = n.parser().parse_args(['--config', str(config), '--quick', '--jobs', '1'])
            with mock.patch.object(n, 'ReadController', return_value=client), \
                 mock.patch.object(n, 'ensure_core', return_value=Path('fake')), \
                 mock.patch.object(n, 'PrivateCore', return_value=core), \
                 mock.patch.object(n, 'check_curl'), \
                 mock.patch.object(n, 'curl_measure', side_effect=n.Interrupted()), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(n.Interrupted):
                    n.run(args)
            core.__exit__.assert_called_once()
            self.assertEqual(client.get.call_args_list[-1].args, ('/proxies',))

    def test_synthetic_quick_run(self):
        proxies = {'AI专用': {'type': 'URLTest', 'all': ['TestNode', 'DIRECT'], 'now': 'TestNode'},
                   'TestNode': {'type': 'Http'}, 'DIRECT': {'type': 'Direct'}}
        client = mock.Mock()
        client.get.side_effect = lambda path: {'all': ['TestNode', 'DIRECT']} if path != '/proxies' else {'proxies': proxies}
        core = mock.MagicMock()
        core.__enter__.return_value = core
        core.available = {'TestNode'}
        core.config = {'listeners': [{'proxy': 'T1', 'port': 54321}]}
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'source.yaml'
            # A one-letter secret must not corrupt phase/kind or double-redact joins.
            config.write_text(SOURCE.replace('synthetic-controller-token', 'e'))
            args = n.parser().parse_args(['--config', str(config), '--quick', '--rounds', '2', '--jobs', '1', '--out', directory])
            with mock.patch.object(n, 'ReadController', return_value=client), \
                 mock.patch.object(n, 'ensure_core', return_value=Path('fake')), \
                 mock.patch.object(n, 'PrivateCore', return_value=core), \
                 mock.patch.object(n, 'check_curl'), \
                 mock.patch.object(n, 'curl_measure', side_effect=lambda *a, **kw: [sample(), sample(connects=0)]) as measure, \
                 mock.patch.object(n, 'trace_location', return_value='JP'), \
                 mock.patch.object(n, 'gemini_check', return_value={'status': '不可用', 'country': 'SGP', 'sample': sample()}), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                n.run(args)
            self.assertEqual(measure.call_count, 6)
            self.assertEqual(core.select.call_count, 2)
            self.assertIn('策略组 now 一致', output.getvalue())
            core.__exit__.assert_called_once()
            self.assertEqual(len(list(Path(directory).glob('*-raw.csv'))), 1)
            for path in Path(directory).glob('*-raw.csv'):
                text = path.read_text(encoding='utf-8-sig')
                for secret in ('node.example.invalid', 'synthetic-password', 'synthetic-controller-token'):
                    self.assertNotIn(secret, text)
                self.assertIn(',latency,', text)
                self.assertIn(',cold,', text)
            self.assertIn('延迟合格', output.getvalue())
            self.assertIn('延迟合格但 Gemini 不可用：TestNode', output.getvalue())
            self.assertIn('不可用(SGP)', output.getvalue())
            self.assertEqual(text.count(',gemini,'), 2)

    def test_no_gemini_skips_check_and_column(self):
        proxies = {'AI专用': {'type': 'Selector', 'all': ['TestNode'], 'now': 'TestNode'}, 'TestNode': {'type': 'Http'}}
        client = mock.Mock()
        client.get.side_effect = lambda path: {'all': ['TestNode']} if path != '/proxies' else {'proxies': proxies}
        core = mock.MagicMock()
        core.__enter__.return_value = core
        core.available = {'TestNode'}
        core.config = {'listeners': [{'proxy': 'T1', 'port': 54321}]}
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'source.yaml'
            config.write_text(SOURCE)
            args = n.parser().parse_args(['--config', str(config), '--quick', '--rounds', '1', '--jobs', '1', '--no-gemini', '--out', directory])
            with mock.patch.object(n, 'ReadController', return_value=client), \
                 mock.patch.object(n, 'ensure_core', return_value=Path('fake')), \
                 mock.patch.object(n, 'PrivateCore', return_value=core), \
                 mock.patch.object(n, 'check_curl'), \
                 mock.patch.object(n, 'curl_measure', side_effect=lambda *a, **kw: [sample(), sample(connects=0)]), \
                 mock.patch.object(n, 'trace_location', return_value='JP'), \
                 mock.patch.object(n, 'gemini_check') as check, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                n.run(args)
            check.assert_not_called()
            self.assertNotIn('Gemini', output.getvalue())

    def test_opaque_names_when_a_credential_is_unparseable(self):
        names = ['美国-abc12', 'Direct-abc12']
        proxies = {'AI专用': {'type': 'URLTest', 'all': names + ['Missing-abc12'], 'now': '美国-abc12'},
                   '美国-abc12': {'type': 'Http'}, 'Direct-abc12': {'type': 'Direct'}}
        after = dict(proxies, **{'AI专用': dict(proxies['AI专用'], now='New-abc12')})
        snapshots = iter([proxies, proxies, after])
        client = mock.Mock()
        client.get.side_effect = lambda path: {'all': names + ['Missing-abc12']} if path != '/proxies' else {'proxies': next(snapshots)}
        core = mock.MagicMock()
        core.__enter__.return_value = core
        core.available = {'美国-abc12'}
        core.config = {'listeners': [{'proxy': 'T1', 'port': 54321}]}
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'source.yaml'
            config.write_text(SOURCE + '  - name: x\n    password: >-\n      abc12\n')
            args = n.parser().parse_args(['--config', str(config), '--quick', '--rounds', '1', '--jobs', '1', '--out', directory])
            with mock.patch.object(n, 'ReadController', return_value=client), \
                 mock.patch.object(n, 'ensure_core', return_value=Path('fake')), \
                 mock.patch.object(n, 'PrivateCore', return_value=core), \
                 mock.patch.object(n, 'check_curl'), \
                 mock.patch.object(n, 'curl_measure', side_effect=lambda *a, **kw: [sample(), sample(connects=0)]), \
                 mock.patch.object(n, 'trace_location', return_value=''), \
                 mock.patch.object(n, 'gemini_check', return_value={'status': '不可用', 'country': 'SGP', 'sample': sample()}), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                n.run(args)
            texts = [output.getvalue()] + [path.read_text(encoding='utf-8-sig') for path in Path(directory).glob('*-*.*') if path != config]
            for text in texts:
                self.assertNotIn('abc12', text)
            self.assertIn('节点#', output.getvalue())
            self.assertIn('未知节点', output.getvalue())
            # Region is inferred from the original name before it is hidden.
            self.assertIn('美国', output.getvalue())

    def test_signal_interruption(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            original = signal.getsignal(sig)
            def interrupt(_args):
                signal.getsignal(sig)(sig, None)
            with mock.patch.object(n, 'run', side_effect=interrupt), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(n.main([]), 130)
            self.assertIn('已中断', output.getvalue())
            self.assertEqual(signal.getsignal(sig), original)


class ParallelTests(unittest.TestCase):
    def test_bandwidth_runs_on_first_lane_after_parallel_latency(self):
        names = ['A', 'B', 'C']
        proxies = {name: {'type': 'Http'} for name in names}
        proxies['AI专用'] = {'type': 'Selector', 'now': 'A', 'all': names}
        client = mock.Mock()
        client.get.side_effect = lambda path: {'all': names} if path != '/proxies' else {'proxies': proxies}
        core = mock.MagicMock()
        core.__enter__.return_value = core
        core.available = set(names)
        core.config = {'listeners': [{'proxy': 'T%d' % i, 'port': 40000 + i} for i in range(1, 4)]}
        current, lock = {}, threading.Lock()
        latency_calls, bandwidth_calls = [], []
        main_thread = threading.get_ident()
        def select(name, group='T1'):
            with lock:
                current[group] = name
            if threading.get_ident() == main_thread:
                self.assertEqual(group, 'T1')
        def measure(port, url, timeout, **kwargs):
            with lock:
                name = current['T%d' % (port - 40000)]
                if kwargs.get('twice'):
                    latency_calls.append(name)
                    return [sample(), sample(connects=0)]
                self.assertEqual(len(latency_calls), 18)
                self.assertEqual(threading.get_ident(), main_thread)
                self.assertEqual(port, 40001)
                self.assertFalse(any(thread.name.startswith('nodetest-') for thread in threading.enumerate()))
                bandwidth_calls.append(name)
                return [sample(size=1024 * 1024, exitcode=28)]
        core.select.side_effect = select
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'source.yaml'
            config.write_text(SOURCE)
            args = n.parser().parse_args(['--config', str(config), '--rounds', '2', '--jobs', '3', '--out', directory])
            with mock.patch.object(n, 'ReadController', return_value=client), \
                 mock.patch.object(n, 'ensure_core', return_value=Path('fake')), \
                 mock.patch.object(n, 'PrivateCore', return_value=core), \
                 mock.patch.object(n, 'check_curl'), \
                 mock.patch.object(n, 'curl_measure', side_effect=measure), \
                 mock.patch.object(n, 'trace_location', return_value='JP'), \
                 mock.patch.object(n, 'gemini_check', return_value={'status': '不可用', 'country': 'SGP', 'sample': sample()}), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                n.run(args)
            self.assertEqual(Counter(latency_calls), {name: 6 for name in names})
            self.assertEqual(Counter(bandwidth_calls), {name: 2 for name in names})
            self.assertIn('实际总用时', output.getvalue())

    def test_defaults_and_jobs_range(self):
        args = n.parser().parse_args([])
        self.assertEqual((args.jobs, args.rounds, args.timeout), (4, 3, 8))
        for value in ('0', '9', '-1', 'bad'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                n.parser().parse_args(['--jobs', value])
            self.assertEqual(caught.exception.code, 2)
        for value in (1, 8):
            self.assertEqual(n.parser().parse_args(['--jobs', str(value)]).jobs, value)
        args.jobs = 9
        with mock.patch.object(n, 'find_config', side_effect=AssertionError('must not read')), self.assertRaises(n.UserError):
            n.run(args)
        with self.assertRaises(n.UserError):
            n.private_files(SOURCE, 0)

    def test_assignments_cover_each_node_once_per_round(self):
        for count in (1, 3, 23):
            nodes = [('node-%d' % i, 'Http') for i in range(count)]
            for jobs in (1, 4, 8):
                for round_no in (1, 2, 3):
                    assignments = n.round_assignments(nodes, jobs, round_no)
                    self.assertEqual(len(assignments), jobs)
                    self.assertEqual(Counter(node for lane in assignments for node in lane), Counter(nodes))
                    self.assertLessEqual(max(map(len, assignments)) - min(map(len, assignments)), 1)
                if count > 1:
                    self.assertNotEqual(n.round_assignments(nodes, jobs, 1)[0][0],
                                        n.round_assignments(nodes, jobs, 2)[0][0])

    def test_parallel_lanes_and_round_barrier(self):
        nodes = [('node-%d' % i, 'Http') for i in range(6)]
        targets = [('one', 'https://example.org/'), ('two', 'https://example.net/')]
        core = mock.Mock()
        core.config = {'listeners': [{'proxy': 'T%d' % i, 'port': 40000 + i} for i in range(1, 4)]}
        by_port = {item['port']: item['proxy'] for item in core.config['listeners']}
        expected = {group: [] for group in by_port.values()}
        for round_no in range(1, 4):
            for index, assigned in enumerate(n.round_assignments(nodes, 3, round_no), 1):
                expected['T%d' % index].extend((round_no, name) for name, _ in assigned)
        lock = threading.Lock()
        release = threading.Event()
        active = peak = 0
        current, records = {}, []
        main_thread = threading.get_ident()

        def select(name, group):
            with lock:
                round_no, expected_name = expected[group].pop(0)
                self.assertEqual(name, expected_name)
                self.assertTrue(threading.current_thread().daemon)
                self.assertEqual(threading.current_thread().name, 'nodetest-' + group)
                if round_no > 1:
                    self.assertEqual(sum(record[3] == round_no - 1 for record in records), len(nodes) * len(targets) * 2)
                current[group] = name

        def measure(port, url, timeout, **kwargs):
            nonlocal active, peak
            with lock:
                name = current[by_port[port]]
                active += 1
                peak = max(peak, active)
                if active == 3:
                    release.set()
            self.assertTrue(release.wait(2), 'workers must overlap')
            with lock:
                active -= 1
                self.assertEqual(current[by_port[port]], name)
            return [dict(sample(), note=name), dict(sample(connects=0), note=name)]

        def record(*args):
            self.assertEqual(threading.get_ident(), main_thread)
            self.assertEqual(args[0], args[-1]['note'])
            with lock:
                records.append(args)

        core.select.side_effect = select
        with mock.patch.object(n, 'curl_measure', side_effect=measure), \
             mock.patch.object(n, 'trace_location', return_value='JP'), contextlib.redirect_stdout(io.StringIO()):
            n.measure_latency(core, nodes, targets, 3, 8, record, {}, False)
        self.assertEqual(peak, 3)
        self.assertTrue(all(not entries for entries in expected.values()))
        self.assertEqual(Counter((args[3], args[0]) for args in records),
                         Counter({(r, name): 4 for r in range(1, 4) for name, _ in nodes}))

    def test_trace_retries_until_success(self):
        core = mock.Mock()
        core.config = {'listeners': [{'proxy': 'T1', 'port': 40001}, {'proxy': 'T2', 'port': 40002}]}
        current, attempts, regions = {}, Counter(), {}
        lock = threading.Lock()
        def select(name, group):
            with lock:
                current[group] = name
        def trace(port, timeout, **kwargs):
            with lock:
                name = current['T%d' % (port - 40000)]
                attempts[name] += 1
                return 'US' if name == 'A' and attempts[name] > 1 else ''
        core.select.side_effect = select
        with mock.patch.object(n, 'curl_measure', return_value=[sample(), sample()]), \
             mock.patch.object(n, 'trace_location', side_effect=trace), contextlib.redirect_stdout(io.StringIO()):
            n.measure_latency(core, [('A', 'Http'), ('B', 'Http')], [('web', 'https://example.org/')],
                              3, 8, lambda *args: None, regions, False)
        self.assertEqual(attempts, {'A': 2, 'B': 3})
        self.assertEqual(regions, {'A': 'US'})

    def test_gemini_retries_only_undetermined(self):
        core = mock.Mock()
        core.config = {'listeners': [{'proxy': 'T1', 'port': 40001}]}
        current, attempts, gemini = {}, Counter(), {}
        core.select.side_effect = lambda name, group: current.__setitem__(group, name)
        def check(port, timeout, **kwargs):
            name = current['T1']
            attempts[name] += 1
            if name == 'C':
                return {'status': '未知', 'country': 'FRA', 'reason': '需同意页', 'sample': sample()}
            status = '可用' if name == 'A' else '不可用' if attempts[name] > 1 else '未知'
            return {'status': status, 'country': 'USA', 'reason': '', 'sample': sample()}
        with mock.patch.object(n, 'curl_measure', return_value=[sample(), sample()]), \
             mock.patch.object(n, 'trace_location', return_value='US'), \
             mock.patch.object(n, 'gemini_check', side_effect=check), contextlib.redirect_stdout(io.StringIO()):
            n.measure_latency(core, [('A', 'Http'), ('B', 'Http'), ('C', 'Http')], [('web', 'https://example.org/')],
                              3, 8, lambda *args: None, {}, False, gemini)
        self.assertEqual(attempts, {'A': 1, 'B': 2, 'C': 1})
        self.assertEqual({name: item['status'] for name, item in gemini.items()}, {'A': '可用', 'B': '不可用', 'C': '未知'})
        self.assertEqual(gemini['B']['round'], 2)

    def test_interruption_during_gemini_check_propagates(self):
        core = mock.Mock()
        core.config = {'listeners': [{'proxy': 'T1', 'port': 40001}]}
        with mock.patch.object(n, 'curl_measure', return_value=[sample(), sample()]), \
             mock.patch.object(n, 'trace_location', return_value='US'), \
             mock.patch.object(n, 'gemini_check', side_effect=n.Interrupted()) as check, \
             mock.patch.object(n.CurlRunner, 'cancel') as cancel, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(n.Interrupted):
                n.measure_latency(core, [('A', 'Http')], [('web', 'https://example.org/')],
                                  2, 8, lambda *args: None, {}, False, {})
        check.assert_called_once()
        cancel.assert_called()

    def test_signals_reap_worker_curl_and_clean_private_directory(self):
        # stage 'gemini': latency/trace return at once, so the hung curl is the real gemini_check.
        for stage, sig in [(stage, sig) for stage in ('latency', 'gemini')
                           for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]:
            processes, ready = [], threading.Event()
            lock = threading.Lock()
            communicating = [0]

            class FakeCurl:
                def __init__(self):
                    self.stdout, self.stderr = io.StringIO(), None
                    self.returncode = None
                    self.killed = threading.Event()
                    self.waited = False
                def communicate(self, timeout):
                    with lock:
                        communicating[0] += 1
                        if communicating[0] == 2:
                            ready.set()
                    if not self.killed.wait(3):
                        raise subprocess.TimeoutExpired('synthetic-curl', timeout)
                    return '', None
                def poll(self):
                    return self.returncode
                def kill(self):
                    self.returncode = -9
                    self.killed.set()
                def wait(self):
                    self.waited = True
                    return self.returncode

            def spawn(*args, **kwargs):
                self.assertEqual(n.GEMINI_URL in args[0], stage == 'gemini')
                process = FakeCurl()
                processes.append(process)
                return process
            def signal_on_wait(*args, **kwargs):
                self.assertTrue(ready.wait(2))
                signal.getsignal(sig)(sig, None)

            core = n.PrivateCore('synthetic-core', SOURCE, 2)
            with mock.patch.object(n.socket, 'socket', side_effect=fake_socket_factory()):
                core.directory, core.config, core.sockets = n.private_files(SOURCE, 2)
            directory = core.directory
            core.process = mock.Mock()
            core.process.poll.return_value = None
            core.select = mock.Mock()
            runner = n.CurlRunner()
            def run(args):
                try:
                    if stage == 'gemini':
                        with mock.patch.object(n, 'curl_measure', return_value=[sample(), sample()]), \
                             mock.patch.object(n, 'trace_location', return_value='US'):
                            n.measure_latency(core, [('A', 'Http'), ('B', 'Http')], [('web', 'https://example.org/')],
                                              1, 8, lambda *args: None, {}, False, {})
                    else:
                        n.measure_latency(core, [('A', 'Http'), ('B', 'Http')], [('web', 'https://example.org/')],
                                          1, 8, lambda *args: None, {}, False)
                finally:
                    core.close()
            try:
                with mock.patch.object(n, 'run', side_effect=run), \
                     mock.patch.object(n, 'CurlRunner', return_value=runner), \
                     mock.patch.object(n.subprocess, 'Popen', side_effect=spawn), \
                     mock.patch.object(n.queue.Queue, 'get', side_effect=signal_on_wait), \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(n.main([]), 130)
                self.assertIn('已中断', output.getvalue())
                self.assertEqual(len(processes), 2)
                self.assertTrue(all(process.killed.is_set() and process.waited for process in processes))
                self.assertFalse(runner.processes)
                self.assertFalse(directory.exists())
                core.process.terminate.assert_called_once()
                self.assertFalse(any(thread.name.startswith('nodetest-') for thread in threading.enumerate()))
            finally:
                runner.cancel()
                core.close()


class DownloadTests(unittest.TestCase):
    def test_verified_atomic_install_and_cache(self):
        content = b'synthetic executable, never run'
        archive = gzip.compress(content)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {'XDG_CACHE_HOME': directory}), \
             mock.patch.object(n.platform, 'system', return_value='Linux'), \
             mock.patch.object(n.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(n, 'SHA256', hashlib.sha256(archive).hexdigest()), \
             mock.patch.object(n.urllib.request, 'urlopen', return_value=io.BytesIO(archive)) as download, \
             contextlib.redirect_stdout(io.StringIO()):
            binary = n.ensure_core()
            self.assertEqual(binary.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
            self.assertEqual(n.ensure_core(), binary)
            download.assert_called_once()
            self.assertEqual(list(binary.parent.iterdir()), [binary])

    def test_failed_checksum_is_not_installed(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {'XDG_CACHE_HOME': directory}), \
             mock.patch.object(n.platform, 'system', return_value='Linux'), \
             mock.patch.object(n.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(n.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong archive')), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(n.UserError):
                n.ensure_core()
            self.assertEqual(list((Path(directory) / 'nodetest').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
