#!/usr/bin/env python3
"""Private mihomo node measurements; Python 3.8+, standard library only."""
import argparse
import csv
import ctypes
import datetime as dt
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import queue
import re
import secrets
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.parse
import urllib.request

VERSION = '1.19.32'
ASSET = 'mihomo-linux-amd64-compatible-v1.19.32.gz'
DOWNLOAD = 'https://github.com/MetaCubeX/mihomo/releases/download/v' + VERSION + '/' + ASSET
SHA256 = 'ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20'
DEFAULT_TARGETS = [('google', 'https://www.google.com/generate_204'),
                   ('cloudflare', 'https://cp.cloudflare.com/generate_204'),
                   ('chatgpt', 'https://chatgpt.com/')]
TRACE_URL = 'https://www.cloudflare.com/cdn-cgi/trace'
GEMINI_URL = 'https://gemini.google.com/app'
GEMINI_MAX_BYTES = 4 * 1024 * 1024
BW_URL = 'https://speed.cloudflare.com/__down?bytes={}'
GROUP_TYPES = {'selector', 'urltest', 'fallback', 'loadbalance', 'relay'}
SKIP_TYPES = GROUP_TYPES | {'direct', 'reject', 'rejectdrop', 'pass', 'compatible'}
PROXY_ENV = {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}
REGION_NAMES = {'US': '美国', 'JP': '日本', 'SG': '新加坡', 'HK': '香港',
                'TW': '台湾', 'KR': '韩国', 'GB': '英国', 'FR': '法国',
                'DE': '德国', 'NL': '荷兰', 'CA': '加拿大', 'AU': '澳大利亚',
                'IN': '印度', 'MY': '马来西亚', 'TH': '泰国', 'ID': '印尼',
                'VN': '越南', 'PH': '菲律宾', 'TR': '土耳其', 'RU': '俄罗斯'}
REGIONS = tuple(REGION_NAMES.values())
FIELDS = 'host label time group phase round node node_type target kind http_code appconnect_ms ttfb_ms total_ms bytes mbps note'.split()
CURL_FORMAT = '\nNODETEST\t%{http_code}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}\t%{size_download}\t%{exitcode}\t%{num_connects}\n'


class UserError(Exception):
    pass


class Interrupted(Exception):
    pass


def validate_url(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ''
        if not host.isascii():
            # IDN mapping can turn full-width letters or soft hyphens into a blocked name.
            raise ValueError()
        if not re.fullmatch(r'[A-Za-z0-9._-]+|\[?[0-9A-Fa-f:.]+\]?', host):
            # Braces, brackets and other punctuation would be curl glob or parser input.
            raise ValueError()
        decoded = host.encode('ascii').decode('idna')
        if (parsed.scheme not in ('http', 'https') or not host or
                '%' in host or '\\' in url or
                parsed.username is not None or parsed.password is not None or
                any(word in decoded.lower() for word in ('claude', 'anthropic')) or
                any(c.isspace() or ord(c) < 32 for c in url)):
            raise ValueError()
        parsed.port
    except (ValueError, UnicodeError):
        raise UserError('测试 URL 无效或含被禁止的 Claude/Anthropic 主机名。')
    return url


def clean_env(env=None):
    return {k: v for k, v in (os.environ if env is None else env).items()
            if k.lower() not in PROXY_ENV}


YAML_ESCAPES = {'0': '\0', 'a': '\a', 'b': '\b', 't': '\t', '\t': '\t', 'n': '\n', 'v': '\v',
                'f': '\f', 'r': '\r', 'e': '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\',
                'N': '\x85', '_': '\xa0', 'L': '\u2028', 'P': '\u2029'}


def yaml_double_quoted(body):
    def escape(match):
        text = match.group(1)
        if text[0] in 'xuU':
            return chr(int(text[1:], 16))
        if text not in YAML_ESCAPES:
            raise ValueError()
        return YAML_ESCAPES[text]
    return re.sub(r'\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)', escape, body)


def scalar(value):
    value = value.strip()
    # Anchors and tags (`&a value`, `!!str value`) precede the actual scalar.
    while re.match(r'(?:&|!)\S*\s+\S', value):
        value = value.split(None, 1)[1]
    if value[:1] in ('|', '>', '*', '&', '!'):
        raise UserError('配置字符串使用了不支持的 YAML 写法。')
    if value.startswith('"'):
        match = re.match(r'"((?:\\.|[^"\\])*)"', value)
        try:
            if not match:
                raise ValueError()
            return yaml_double_quoted(match.group(1))
        except ValueError:
            raise UserError('配置字符串格式不受支持；请用 --controller/--secret 指定。') from None
    if value.startswith("'"):
        match = re.match(r"'((?:[^']|'')*)'", value)
        if not match:
            raise UserError('控制器配置字符串格式无效。')
        return match.group(1).replace("''", "'")
    return re.split(r'\s+#', value, maxsplit=1)[0].strip()


def normalize_controller(address):
    if address.startswith((':', '0.0.0.0:')):
        address = '127.0.0.1:' + address.rsplit(':', 1)[1]
    if '://' not in address:
        address = 'http://' + address
    try:
        p = urllib.parse.urlsplit(address)
        # Only loopback controllers: do not transmit secrets to remote hosts.
        if (p.scheme != 'http' or p.username or p.password or
                p.hostname not in ('127.0.0.1', 'localhost', '::1') or
                not p.port or p.path not in ('', '/') or p.query or p.fragment):
            raise ValueError()
    except ValueError:
        raise UserError('控制器必须是 loopback HTTP 地址，例如 127.0.0.1:9090。')
    return address.rstrip('/')


def read_controller(text):
    values = {}
    for line in text.splitlines():
        match = re.match(r'^(external-controller|secret):\s*(.*)$', line)
        if match:
            try:
                values[match.group(1)] = scalar(match.group(2))
            except UserError:
                # Unparseable here is fine when --controller/--secret override it; run() checks.
                values[match.group(1)] = None
    return values.get('external-controller'), values.get('secret', '')


def find_config():
    if os.environ.get('APPDATA'):
        path = Path(os.environ['APPDATA']) / 'com.follow/clash/config.yaml'
        if path.is_file():
            return path
    hits = sorted(Path('/mnt/c/Users').glob('*/AppData/Roaming/com.follow/clash/config.yaml'))
    return hits[0] if hits else None


def redact(text, sensitive=()):
    # One pass over distinct values: replacements are never rescanned, so output cannot grow
    # recursively. Values shorter than 4 characters are not identifying and would mangle text.
    values = sorted({str(s) for s in sensitive if s and len(str(s)) >= 4}, key=len, reverse=True)
    if values:
        text = re.sub('|'.join(map(re.escape, values)), '[redacted]', text)
    text = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', '[ip]', text)
    text = re.sub(r'(?i)\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*[a-z]\b', '[host]', text)
    text = re.sub(r'(?i)(?<!\w)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%\w+)?', '[ip]', text)
    text = re.sub(r'(?i)\b[0-9a-f]{8}-[0-9a-f-]{27,}\b', '[id]', text)
    text = re.sub(r'(?i)(password|uuid|secret|server|port)\s*[:=]\s*[^\s,}]+', r'\1=[redacted]', text)
    return ''.join(c if c.isprintable() else ' ' for c in text)


def sensitive_values(text):
    return credential_scan(text)[0]


def credential_scan(text):
    """Return (credential values, whether some value could not be parsed)."""
    # Defense in depth for display names; never expose raw source or stderr.
    values, unparsed = [], False
    keys = 'server|password|uuid|secret|username|auth|auth-str|psk|token|obfs-password|private-key|public-key|short-id'
    pattern = r'''(?i)(?<![\w-])["']?(?:''' + keys + r''')["']?\s*:\s*("(?:\\.|[^"\\])*"|'(?:''|[^'])*'|[^\s,}\]]+)'''
    for match in re.finditer(pattern, text):
        try:
            values.append(str(scalar(match.group(1))))
        except UserError:
            unparsed = True
    # Ports are not collected: values like `port: 0` would mangle names such as 香港02.
    return [value for value in dict.fromkeys(values) if value], unparsed


def safe_name(value):
    value = ''.join(c for c in str(value) if c.isprintable())
    value = re.sub(r'[^\w.\-]+', '_', value, flags=re.UNICODE).strip('._')
    return value[:70] or 'none'


def display_name(value):
    return ''.join(c for c in value if not 0x1F1E6 <= ord(c) <= 0x1F1FF).strip()


def width(value):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in str(value))


def pad(value, size):
    return str(value) + ' ' * max(0, size - width(value))


class ReadController:
    """FlClash interface deliberately has no write operation."""
    def __init__(self, base, secret, timeout=5):
        self.base = normalize_controller(base)
        self.secret = secret
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, path):
        request = urllib.request.Request(self.base + path, headers={'Authorization': 'Bearer ' + self.secret})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return json.load(response)
        except (OSError, ValueError):
            raise UserError('无法读取本地控制器；请检查地址、secret 及客户端状态。') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def selections(proxies):
    return {name: item.get('now', '') for name, item in proxies.items()
            if item.get('type', '').lower() in GROUP_TYPES}


def group_nodes(proxies, members):
    nodes, skipped = [], []
    for name in dict.fromkeys(members):
        item = proxies.get(name)
        if not item or item.get('type', '').lower() in SKIP_TYPES or name.upper() in ('DIRECT', 'REJECT'):
            skipped.append(name)
        else:
            nodes.append((name, item.get('type', 'Unknown')))
    return nodes, skipped


def private_files(source, jobs=4):
    if not 1 <= jobs <= 8:
        raise UserError('--jobs 必须在 1–8 之间。')
    directory = Path(tempfile.mkdtemp(prefix='nodetest-'))
    os.chmod(str(directory), 0o700)
    try:
        # Reserve every listener and controller port together until just before spawn.
        sockets = []
        for _ in range(jobs + 1):
            sock = socket.socket()
            sockets.append(sock)
            sock.bind(('127.0.0.1', 0))
        ports = [sock.getsockname()[1] for sock in sockets]
        config = {'bind-address': '127.0.0.1', 'allow-lan': False,
                  'mode': 'rule', 'log-level': 'warning', 'ipv6': False,
                  'external-controller': '127.0.0.1:' + str(ports[-1]), 'secret': secrets.token_hex(32),
                  'geo-auto-update': False, 'unified-delay': False,
                  'profile': {'store-selected': False, 'store-fake-ip': False},
                  'proxy-providers': {'src': {'type': 'file', 'path': './src.yaml', 'health-check': {'enable': False}}},
                  'proxy-groups': [{'name': 'T%d' % (i + 1), 'type': 'select', 'use': ['src']} for i in range(jobs)],
                  'listeners': [{'name': 'l%d' % (i + 1), 'type': 'mixed', 'listen': '127.0.0.1',
                                 'port': ports[i], 'proxy': 'T%d' % (i + 1)} for i in range(jobs)],
                  'rules': ['MATCH,REJECT']}
        for name, data in [('src.yaml', source), ('config.yaml', json.dumps(config))]:
            fd = os.open(str(directory / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as output:
                output.write(data)
        return directory, config, sockets
    except BaseException:
        for sock in locals().get('sockets', []):
            sock.close()
        shutil.rmtree(str(directory))
        raise


def parent_death_signal(expected_parent=None):
    if sys.platform.startswith('linux'):
        parent = expected_parent if expected_parent is not None else os.getppid()
        try:
            libc = ctypes.CDLL(None)
            libc.prctl(1, signal.SIGKILL)
            if os.getppid() != parent:
                os.kill(os.getpid(), signal.SIGKILL)
        except (OSError, AttributeError):
            pass


class PrivateCore:
    def __init__(self, binary, source, jobs=4):
        self.binary, self.source = binary, source
        self.jobs = jobs
        self.directory = None
        self.process = None
        self.log = None
        self.sockets = []

    def __enter__(self):
        try:
            self.directory, self.config, self.sockets = private_files(self.source, self.jobs)
            self.api = ReadController('127.0.0.1:' + self.config['external-controller'].rsplit(':', 1)[1], self.config['secret'], 0.4)
            # Each lane has its own opener; no shared urllib state between workers.
            self.group_apis = {group['name']: ReadController(self.api.base, self.config['secret'])
                               for group in self.config['proxy-groups']}
            fd = os.open(str(self.directory / 'mihomo.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.log = os.fdopen(fd, 'wb')
            for sock in self.sockets:
                sock.close()
            parent_pid = os.getpid()
            self.process = subprocess.Popen([str(self.binary), '-d', str(self.directory), '-f', str(self.directory / 'config.yaml')],
                                            env=clean_env(), stdout=self.log, stderr=self.log,
                                            preexec_fn=lambda: parent_death_signal(parent_pid))
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and self.process.poll() is None:
                try:
                    available = [set(self.api.get('/proxies/' + group)['all']) for group in self.group_apis]
                    self.available = set.intersection(*available)
                    return self
                except UserError:
                    time.sleep(0.1)
            # Raw logs may contain arbitrary credentials. Emit only allowlisted error categories.
            self.log.flush()
            log = (self.directory / 'mihomo.log').read_text(encoding='utf-8', errors='replace')
            categories = [word for word in ('address already in use', 'permission denied', 'invalid', 'unsupported', 'not found') if word in log.lower()]
            raise UserError('私有 mihomo 启动失败：' + (', '.join(categories) or '配置加载失败或启动超时；请检查内核版本和内联 proxies 配置。'))
        except BaseException:
            self.close()
            raise

    def select(self, name, group='T1'):
        # The only PUT in the program is pinned to this private controller.
        api = self.group_apis[group]
        request = urllib.request.Request(api.base + '/proxies/' + group,
                                         data=json.dumps({'name': name}).encode(), method='PUT',
                                         headers={'Authorization': 'Bearer ' + self.config['secret'], 'Content-Type': 'application/json'})
        try:
            with api.opener.open(request, timeout=5) as response:
                if response.status != 204:
                    raise UserError('私有节点切换失败。')
        except OSError:
            raise UserError('私有节点切换失败。') from None

    def close(self):
        # Hold termination signals until the credential copy is gone; they are delivered afterwards.
        try:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            mask = None
        try:
            self._close()
        finally:
            if mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def _close(self):
        for sock in self.sockets:
            sock.close()
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    try:
                        self.process.terminate()
                        self.process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait()
                    except ProcessLookupError:
                        self.process.wait()
        finally:
            if self.log is not None:
                self.log.close()
            if self.directory is not None and self.directory.exists():
                shutil.rmtree(str(self.directory))

    def __exit__(self, *args):
        self.close()


def ensure_core(explicit=None):
    if explicit:
        binary = Path(explicit).expanduser().resolve()
        if not binary.is_file() or not os.access(str(binary), os.X_OK):
            raise UserError('--mihomo 必须指向可执行的本地内核。')
        return binary
    cache = Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache'))) / 'nodetest'
    binary = cache / ('mihomo-v' + VERSION)
    if binary.is_file() and os.access(str(binary), os.X_OK):
        return binary
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise UserError('自动下载只支持 Linux amd64；请使用 --mihomo 指定内核。')
    print('首次运行：下载并校验 mihomo v' + VERSION + '（下载可使用环境代理）。')
    cache.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='.install-', dir=str(cache)) as temp:
            archive = Path(temp) / 'core.gz'
            digest = hashlib.sha256()
            with urllib.request.urlopen(DOWNLOAD, timeout=60) as response, archive.open('wb') as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != SHA256:
                raise UserError('mihomo 下载校验失败，未安装。')
            unpacked = Path(temp) / 'mihomo'
            with gzip.open(str(archive), 'rb') as source, unpacked.open('wb') as output:
                shutil.copyfileobj(source, output)
            unpacked.chmod(0o755)
            os.replace(str(unpacked), str(binary))
    except (OSError, ValueError, UserError) as error:
        reason = str(error) if isinstance(error, UserError) else 'mihomo 下载/安装失败。'
        raise UserError(reason + '\n手动下载（仅在校验通过后解压执行）：\n  curl -fL ' + DOWNLOAD + ' -o mihomo.gz\n  echo "' + SHA256 + '  mihomo.gz" | sha256sum -c - && gzip -dc mihomo.gz > mihomo && chmod 755 mihomo\n然后传入 --mihomo ./mihomo') from None
    return binary


def curl_reason(code):
    return {0: '', 5: '代理解析失败', 6: '目标解析失败', 7: '连接失败', 18: '响应不完整',
            28: '超时', 35: 'TLS握手失败', 52: '空响应', 56: '接收失败', 60: '证书校验失败',
            63: '超过字节上限', 97: '代理握手失败'}.get(code, 'curl错误') + ('(curl %d)' % code if code else '')


def parse_curl(text):
    results = []
    for line in text.splitlines():
        if not line.startswith('NODETEST\t'):
            continue
        parts = line.split('\t')
        if len(parts) != 8:
            raise UserError('curl 输出格式异常；需要支持 %{exitcode} 的 curl（建议 8.5+）。')
        try:
            http = int(parts[1])
            numbers = [float(value) for value in parts[2:6]]
            if any(not math.isfinite(value) or value < 0 for value in numbers):
                raise ValueError()
            app, ttfb, total, size = numbers
            exitcode, connects = int(parts[6]), int(parts[7])
            results.append({'http_code': http, 'appconnect_ms': app * 1000,
                            'ttfb_ms': ttfb * 1000, 'total_ms': total * 1000,
                            'bytes': int(size), 'exitcode': exitcode, 'connects': connects,
                            'note': curl_reason(exitcode)})
        except ValueError:
            raise UserError('curl 测量数据格式异常。') from None
    return results


def curl_args(port, timeout):
    return ['curl', '-q', '--silent', '--proxy', 'http://127.0.0.1:' + str(port),
            '--noproxy', '', '--proto', '=http,https', '--max-redirs', '0', '--globoff',
            '--connect-timeout', str(timeout), '--max-time', str(timeout),
            '--user-agent', 'nodetest/0.1']


def check_curl():
    if not shutil.which('curl'):
        raise UserError('未找到 curl，请先安装 curl 8.5+。')
    result = subprocess.run(['curl', '-q', '--version'], env=clean_env(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, timeout=5)
    match = re.match(r'curl (\d+)\.(\d+)\.(\d+)', result.stdout)
    if result.returncode or not match or tuple(map(int, match.groups())) < (8, 5, 0):
        raise UserError('需要 curl 8.5+，以支持逐请求退出码和流式下载字节上限。')


class CurlRunner:
    """Own worker subprocesses so the main thread can cancel and reap all curl jobs."""
    def __init__(self):
        self.lock = threading.Lock()
        self.cancelled = threading.Event()
        self.processes = set()

    def check(self):
        if self.cancelled.is_set():
            raise Interrupted()

    @staticmethod
    def stop(process):
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        process.wait()

    def run(self, command, timeout, **kwargs):
        # Hold the lock through spawn/registration: cancellation cannot miss a new child.
        with self.lock:
            self.check()
            process = subprocess.Popen(command, **kwargs)
            self.processes.add(process)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except BaseException:
            self.stop(process)
            raise
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            with self.lock:
                self.processes.discard(process)

    def cancel(self):
        with self.lock:
            self.cancelled.set()
            processes = list(self.processes)
        for process in processes:
            self.stop(process)


def curl_measure(port, url, timeout, twice=False, max_bytes=None, limit_rate=None, runner=None):
    validate_url(url)
    command = curl_args(port, timeout) + ['--write-out', CURL_FORMAT]
    if max_bytes is not None:
        command += ['--max-filesize', str(max_bytes)]
    if limit_rate:
        command += ['--limit-rate', limit_rate]
    for _ in range(2 if twice else 1):
        command += ['--output', os.devnull, '--url', url]
    try:
        execute = runner.run if runner is not None else subprocess.run
        result = execute(command, env=clean_env(), stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, timeout=timeout * (2 if twice else 1) + 5)
        samples = parse_curl(result.stdout)
    except subprocess.TimeoutExpired:
        samples = []
    count = 2 if twice else 1
    if not samples:
        if 'result' in locals() and result.returncode != 0:
            reason = curl_reason(result.returncode)
        else:
            reason = 'curl进程超时'
        samples = [{'http_code': 0, 'appconnect_ms': 0, 'ttfb_ms': 0, 'total_ms': 0,
                    'bytes': 0, 'exitcode': 28, 'connects': 0, 'note': reason} for _ in range(count)]
    if len(samples) != count:
        raise UserError('curl 返回的请求数量异常。')
    return samples


def trace_location(port, timeout, runner=None):
    validate_url(TRACE_URL)
    command = curl_args(port, min(timeout, 5)) + ['--max-filesize', '16384', '--url', TRACE_URL]
    try:
        execute = runner.run if runner is not None else subprocess.run
        result = execute(command, env=clean_env(), stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, timeout=min(timeout, 5) + 5)
        match = re.search(r'^loc=([A-Z]{2})$', result.stdout, re.MULTILINE)
        return match.group(1) if match else ''
    except subprocess.TimeoutExpired:
        return ''


def gemini_verdict(body):
    # The anonymous app page carries Google's per-IP availability flag and its country guess.
    flag = re.search(r'\\?"45631641\\?"\s*:\s*(true|false)(?![\w$])|(?<![\w$])45631641,null,(true|false)(?![\w$])', body)
    country = re.search(r',2,1,200,"([A-Z]{3})"', body)
    status = '未知' if not flag else '可用' if 'true' in (flag.group(1), flag.group(2)) else '不可用'
    reason = ''
    if status == '不可用' and 'consent.google.com/' in body:
        # EEA/UK anonymous visitors get a cookie-consent gate; the flag stays false regardless.
        status, reason = '未知', '需同意页'
    return status, country.group(1) if country else '', reason


def gemini_check(port, timeout, runner=None):
    """Return Gemini availability for the current exit; status is 可用/不可用/未知."""
    validate_url(GEMINI_URL)
    command = curl_args(port, timeout) + ['--compressed', '--max-filesize', str(GEMINI_MAX_BYTES),
                                          '--write-out', CURL_FORMAT, '--url', GEMINI_URL]
    try:
        execute = runner.run if runner is not None else subprocess.run
        result = execute(command, env=clean_env(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         encoding='utf-8', errors='replace', timeout=timeout + 5)
        body, _, tail = result.stdout.rpartition('\nNODETEST\t')
        samples = parse_curl('NODETEST\t' + tail) if tail else []
    except subprocess.TimeoutExpired:
        body, samples = '', []
    sample = samples[0] if samples else {'http_code': 0, 'appconnect_ms': 0, 'ttfb_ms': 0, 'total_ms': 0,
                                          'bytes': 0, 'exitcode': 28, 'connects': 0, 'note': 'curl进程超时'}
    # A timed-out, oversized or incomplete page may lack the flag or the consent marker: never decide on it.
    complete = sample['http_code'] == 200 and sample['exitcode'] == 0
    status, country, reason = gemini_verdict(body) if complete else ('未知', '', '')
    return {'status': status, 'country': country, 'reason': reason, 'sample': sample}


def round_assignments(nodes, jobs, round_no):
    if not nodes:
        return [[] for _ in range(jobs)]
    offset = (round_no - 1) % len(nodes)
    ordered = nodes[offset:] + nodes[:offset]
    return [ordered[index::jobs] for index in range(jobs)]


def measure_latency(core, nodes, targets, rounds, timeout, record, regions, tty, gemini=None):
    """Workers own lanes; only the main thread records samples or prints progress.

    `gemini`, when a dict, receives each node's latest Gemini check; undetermined results
    (未知, except the deterministic consent gate) are retried in later rounds like the country trace."""
    runner = CurlRunner()
    lanes = [(listener['proxy'], listener['port']) for listener in core.config['listeners']]

    def worker(group, port, assigned, known_regions, known_gemini, messages):
        try:
            for name, node_type in assigned:
                runner.check()
                core.select(name, group)
                samples = []
                for target, url in targets:
                    runner.check()
                    pair = curl_measure(port, url, timeout, twice=True, runner=runner)
                    samples.extend((target, kind, sample) for kind, sample in zip(('cold', 'warm'), pair))
                runner.check()
                location = known_regions.get(name) or trace_location(port, timeout, runner=runner)
                check = None
                known = known_gemini.get(name, {}) if known_gemini is not None else None
                if known is not None and known.get('status') in (None, '未知') and not known.get('reason'):
                    runner.check()
                    check = gemini_check(port, timeout, runner=runner)
                messages.put(('node', (name, node_type, samples, location, check)))
        except BaseException as error:
            messages.put(('error', error))
        finally:
            messages.put(('done', None))

    try:
        for round_no in range(1, rounds + 1):
            messages = queue.Queue()
            assignments = round_assignments(nodes, len(lanes), round_no)
            known_regions = dict(regions)
            known_gemini = dict(gemini) if gemini is not None else None
            threads = [threading.Thread(target=worker, args=(group, port, assigned, known_regions, known_gemini, messages),
                                        name='nodetest-' + group, daemon=True)
                       for (group, port), assigned in zip(lanes, assignments)]
            completed = finished = 0
            try:
                for thread in threads:
                    thread.start()
                while finished < len(threads):
                    kind, payload = messages.get()
                    if kind == 'error':
                        raise payload
                    if kind == 'done':
                        finished += 1
                        continue
                    name, node_type, samples, location, check = payload
                    for target, sample_kind, sample in samples:
                        record(name, node_type, 'latency', round_no, target, sample_kind, sample)
                    if location:
                        regions[name] = location
                    if check is not None:
                        gemini[name] = dict(check, round=round_no)
                    completed += 1
                    if tty:
                        print('\r延迟：第 %d/%d 轮，已完成 %d/%d 个节点' % (round_no, rounds, completed, len(nodes)), end='', flush=True)
            except BaseException:
                runner.cancel()
                raise
            finally:
                # Cancellation kills curl first; pending loopback PUTs have a 5-second timeout.
                for thread in threads:
                    if thread.ident is not None:
                        thread.join()
            if not tty:
                print('延迟：完成第 %d/%d 轮（%d/%d 个节点）' % (round_no, rounds, completed, len(nodes)), flush=True)
    finally:
        runner.cancel()
        if tty:
            print()


def region_name(node, code=''):
    if code:
        return REGION_NAMES.get(code, code)
    return next((region for region in REGIONS if region in node), '未知')


def bandwidth(sample):
    duration = (sample['total_ms'] - sample['ttfb_ms']) / 1000
    valid = (sample['http_code'] == 200 and sample['exitcode'] in (0, 28) and
             sample['bytes'] >= 256 * 1024 and duration > 0)
    return sample['bytes'] * 8 / duration / 1e6 if valid else None


def percentile(values, fraction=0.95):
    if not values:
        return float('inf')
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def rank_nodes(nodes, rows, targets, min_mbps, quick=False, regions=None, gemini=None):
    ranked = []
    for name, node_type in nodes:
        latency = [row for row in rows if row['node'] == name and row['phase'] == 'latency']
        failures = sum(not row['http_code'] for row in latency)
        rate = failures / len(latency) if latency else 1
        reasons = []
        if rate > 0.2:
            reasons.append('失败率>20%')
        medians = {}
        for target in targets:
            for kind in ('cold', 'warm'):
                values = [row['ttfb_ms'] for row in latency if row['target'] == target and row['kind'] == kind and row['http_code']]
                medians[(target, kind)] = statistics.median(values) if values else float('inf')
            if not any(row['http_code'] for row in latency if row['target'] == target):
                reasons.append(target + '全失败')
        cold = [row['ttfb_ms'] for row in latency if row['kind'] == 'cold' and row['http_code']]
        # The 32 MiB deep test is the better estimate of sustained speed; fall back to the 8 MiB screen.
        speeds = {row['phase']: row['mbps'] for row in rows if row['node'] == name and row['phase'] in ('bw1', 'bw2') and row.get('mbps') is not None}
        speed = speeds.get('bw2', speeds.get('bw1'))
        mean = statistics.mean(medians[(target, 'cold')] for target in targets)
        p95 = percentile(cold)
        region = region_name(name, (regions or {}).get(name, ''))
        ranked.append({'node': name, 'type': node_type, 'region': region, 'medians': medians,
                       'gemini': (gemini or {}).get(name),
                       'mean': mean, 'p95': p95, 'failure_rate': rate, 'mbps': speed,
                       'reasons': reasons, 'qualified': speed is not None and speed >= min_mbps})
    return sorted(ranked, key=lambda item: (bool(item['reasons']), False if quick else not item['qualified'], item['mean'], item['p95'], item['node']))


def number(value):
    return '-' if value is None or not math.isfinite(value) else '%.0f' % value


def gemini_label(check):
    if not check:
        return '-'
    detail = '·'.join(filter(None, [check.get('country'), check.get('reason')]))
    return check['status'] + ('(%s)' % detail if detail else '')


def make_summary(ranked, targets, skipped, before, after, quick, minimum,
                 changed_names=None):
    show_gemini = any(item.get('gemini') for item in ranked)
    headings = ['节点', '类型', '地区'] + (['Gemini'] if show_gemini else []) + [target + '冷/复用ms' for target in targets] + ['冷p95ms', '失败率', 'Mbps', '状态']
    table = [headings]
    for item in ranked:
        table.append([display_name(item['node']), item['type'], item['region']] +
                     ([gemini_label(item.get('gemini'))] if show_gemini else []) +
                     [number(item['medians'][(target, 'cold')]) + '/' + number(item['medians'][(target, 'warm')]) for target in targets] +
                     [number(item['p95']), '%.1f%%' % (item['failure_rate'] * 100), number(item['mbps']),
                      '淘汰：' + '、'.join(item['reasons']) if item['reasons'] else ('延迟合格' if quick else '带宽达标' if item['qualified'] else '带宽未达标/未可信测得')])
    sizes = [max(width(row[i]) for row in table) for i in range(len(headings))]
    lines = ['  '.join(pad(value, sizes[i]) for i, value in enumerate(row)).rstrip() for row in table]
    eligible = [item for item in ranked if not item['reasons']]
    recommended = eligible if quick else [item for item in eligible if item['qualified']]
    no_gemini = lambda item: show_gemini and (item.get('gemini') or {}).get('status') == '不可用'
    lines += ['', '建议长期固定（本次候选）：' + ('、'.join(display_name(item['node']) + ('（Gemini 不可用）' if no_gemini(item) else '')
                                                    for item in recommended[:3]) or '无；本次没有满足延迟及带宽门槛的节点')]
    if show_gemini:
        usable = [item for item in recommended if (item.get('gemini') or {}).get('status') == '可用']
        lines.append('兼顾 Gemini 的候选：' + ('、'.join(display_name(item['node']) for item in usable[:3]) or '无'))
        lines.append(('延迟合格' if quick else '带宽达标') + '但 Gemini 不可用：' +
                     ('、'.join(display_name(item['node']) for item in recommended if no_gemini(item)) or '无'))
    if quick:
        lines.append('quick 模式只按延迟推荐，带宽未验证。')
    else:
        lines.append('带宽门槛：%g Mbps；有深测（32 MiB）用深测速度，否则用初筛（8 MiB）。' % minimum)
    best = {}
    for item in eligible:
        best.setdefault(item['region'], item)
    lines.append('各地区最佳：' + ('；'.join(region + '=' + display_name(item['node']) for region, item in best.items()) or '无'))
    lines.append('跳过子组/DIRECT/REJECT/未知成员：' + ('、'.join(skipped) or '无'))
    if after is None:
        lines.append('FlClash 策略组：结束快照读取失败，无法核对变化；本工具对其仅发送 GET。')
    else:
        changed = changed_names if changed_names is not None else [name for name in sorted(set(before) | set(after)) if before.get(name) != after.get(name)]
        lines.append('FlClash 策略组：' + ('发生变化：' + '、'.join(changed) + '。URLTest 等组可能自主切换；本工具未切换客户端。' if changed else '测试前后所有策略组 now 一致；本工具仅发送 GET。'))
    for name in sorted(set(before) | set(after or {})):
        lines.append('  %s：测试前=%s；测试后=%s' % (name, before.get(name, '(不存在)'),
                     after.get(name, '(不存在)') if after is not None else '(未取得)'))
    lines += ['冷连接 TTFB 含代理拨号、节点握手和目标 TLS；appconnect 另存 CSV，time_connect 只是连接本地代理。',
              'tuic/hysteria2 等 QUIC 节点会话可能被内核复用，冷连接不一定包含节点握手。',
              '复用列是同一 curl 进程的第二次请求；服务器关闭连接时会重连（CSV note 标明）。',
              '收到任何 HTTP 响应即算延迟成功，包括 403/429；它们不表示目标服务可正常使用。',
              '失败率含冷/复用全部请求；p95 使用所有目标成功冷请求的最近秩分位数。',
              '小文件下载偏向起速快的节点；带宽超时允许使用已收到字节，少于 256 KiB 不可信。',
              '地区优先使用 Cloudflare trace 的 loc（仅保存地区，不保存出口 IP），失败时从节点名推断。',
              '单次结果不代表长期稳定，建议不同时段复测。UDP 节点失败也可能来自 WSL/防火墙限制。',
              'URLTest 组的固定选择在节点失联时仍会自动换；要真正钉死，应在上层 Selector 组直接选具体节点。']
    if show_gemini:
        lines.append('Gemini 列：匿名请求 gemini.google.com/app（不登录、不带 cookie），读页面里 Google 按出口 IP 给的可用开关；'
                     '括号内是 Google 判定的国家（ISO3），可与 Cloudflare 地区不同。国家受支持仍不可用，通常是出口 IP 被 Google 限制；'
                     '“未知”表示请求失败、非 200 或页面改版找不到开关；“需同意页”是欧盟/英国等出口匿名访问先要同意 cookie，'
                     '开关恒为 false，无法匿名判定，请在浏览器里核实。Gemini 结果不参与淘汰和排序。')
    return '\n'.join(lines) + '\n'


def write_results(out, host, label, group, rows, summary):
    out = Path(out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    prefix = dt.datetime.now().strftime('%Y%m%d-%H%M') + '-' + safe_name(host) + '-' + safe_name(label)
    # Keep the requested basename while preserving earlier runs within the same minute.
    base = prefix
    index = 2
    while (out / (base + '-summary.txt')).exists() or (out / (base + '-raw.csv')).exists():
        base = prefix + '-' + str(index)
        index += 1
    summary_path, raw_path = out / (base + '-summary.txt'), out / (base + '-raw.csv')
    with summary_path.open('x', encoding='utf-8') as output:
        output.write(summary)
    with raw_path.open('x', encoding='utf-8-sig', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            data = dict(row, host=host, label=label, group=group)
            # Avoid spreadsheet formulas in untrusted names/labels.
            data = {key: ("'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@')) else value) for key, value in data.items()}
            writer.writerow(data)
    return summary_path, raw_path


def parser():
    p = argparse.ArgumentParser(description='通过私有 mihomo 测试节点；不改变正在运行的代理客户端。')
    p.add_argument('--group', default='AI专用', help='待测策略组（默认 AI专用）')
    p.add_argument('--label', default='', help='地点标签，进入报告和文件名')
    p.add_argument('--ask-label', action='store_true', help='交互询问地点标签，回车跳过')
    p.add_argument('--rounds', type=int, default=3, help='延迟轮数（默认 3）')
    p.add_argument('--timeout', type=float, default=8, help='单次延迟超时秒数（默认 8）')
    p.add_argument('--jobs', type=int, choices=range(1, 9), default=4, metavar='N',
                   help='延迟并发 worker 数（1–8，默认 4）；带宽始终串行')
    p.add_argument('--target', action='append', metavar='名称=URL', help='重复指定以替换全部默认目标；禁止 Claude/Anthropic 主机')
    p.add_argument('--quick', action='store_true', help='只测延迟，跳过带宽')
    p.add_argument('--no-gemini', action='store_true', help='跳过每节点一次的 Gemini 可用性检测')
    p.add_argument('--limit-rate', help='带宽测试 curl 限速，例如 2M')
    p.add_argument('--min-mbps', type=float, default=10, help='推荐带宽门槛（默认 10 Mbps）')
    p.add_argument('--config', type=Path, help='Clash 内联 proxies 配置；默认自动寻找 FlClash 配置')
    p.add_argument('--controller', help='FlClash loopback 控制器地址；默认从配置读取')
    p.add_argument('--secret', help='控制器 secret；建议从配置读取以免留在 shell 历史中')
    p.add_argument('--mihomo', help='本地可执行内核；否则自动缓存固定 v1.19.32（仅 Linux amd64）')
    p.add_argument('--out', default='~/nettest/results', help='结果目录（默认 ~/nettest/results）')
    p.add_argument('--list-groups', action='store_true', help='只读列出客户端策略组后退出')
    return p


def run(args):
    started = time.monotonic()
    if not 1 <= args.jobs <= 8:
        raise UserError('--jobs 必须在 1–8 之间。')
    if args.rounds < 1 or not math.isfinite(args.timeout) or args.timeout <= 0 or not math.isfinite(args.min_mbps) or args.min_mbps < 0:
        raise UserError('轮数必须为正整数，超时须为正数，带宽门槛须为非负数。')
    if args.limit_rate and not re.fullmatch(r'[1-9][0-9]*(?:[kKmMgG])?', args.limit_rate):
        raise UserError('--limit-rate 格式无效，例如 2M 或 512K。')
    targets = []
    for target in args.target or []:
        if '=' not in target:
            raise UserError('--target 格式为 名称=URL。')
        name, url = target.split('=', 1)
        if not name.strip() or name in [item[0] for item in targets]:
            raise UserError('目标名称不能为空或重复。')
        targets.append((name, validate_url(url)))
    targets = targets or list(DEFAULT_TARGETS)
    for _, url in targets:
        validate_url(url)
    validate_url(TRACE_URL)
    validate_url(GEMINI_URL)
    validate_url(BW_URL.format(8 * 1024 * 1024))
    config_path = args.config.expanduser() if args.config else find_config()
    if config_path is None:
        raise UserError('未找到 FlClash 配置；请用 --config 指定。')
    try:
        source = config_path.read_text(encoding='utf-8-sig')
    except OSError:
        raise UserError('无法读取配置文件。') from None
    base, secret = read_controller(source)
    base = args.controller or base
    secret = args.secret if args.secret is not None else secret
    if not base:
        raise UserError('配置没有可用的 external-controller；请用 --controller 指定。')
    if secret is None:
        raise UserError('配置中的 secret 无法解析；请用 --secret 指定。')
    base = normalize_controller(base)
    sensitive, unparsed = credential_scan(source)
    sensitive.append(secret)
    client = ReadController(base, secret)
    proxies = client.get('/proxies')['proxies']
    # If some credential could not be parsed, node names cannot be checked against it:
    # show opaque ordinals instead of names.
    public = lambda value: redact(str(value), sensitive)
    groups = {name for name, item in proxies.items() if item.get('type', '').lower() in GROUP_TYPES}
    builtins = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'}
    opaque = {name: '节点#%d' % index for index, name in
              enumerate((name for name in proxies if name not in groups | builtins), 1)} if unparsed else {}

    def public_name(value):
        # Any name that is not a known group or builtin may embed the unparsed credential.
        if not unparsed or value in groups | builtins:
            return public(value)
        return opaque.get(value, '未知节点')
    if args.list_groups:
        for name, item in proxies.items():
            if item.get('type', '').lower() in GROUP_TYPES:
                print('%s  %s  %d 个成员' % (public_name(name), item['type'], len(item.get('all', []))))
        return
    check_curl()
    if not re.search(r'^proxies:\s*(?:#.*)?$', source, re.MULTILINE) and not re.search(r'^proxies:\s*\[', source, re.MULTILINE):
        raise UserError('仅支持含内联 proxies 列表的 Clash YAML 配置。')
    if args.group not in proxies or proxies[args.group].get('type', '').lower() not in GROUP_TYPES:
        raise UserError('未找到待测策略组；用 --list-groups 查看。')
    members = client.get('/proxies/' + urllib.parse.quote(args.group, safe=''))['all']
    nodes, skipped = group_nodes(proxies, members)
    if not nodes:
        raise UserError('策略组内没有可测试的具体节点。')
    if args.ask_label:
        try:
            args.label = input('地点标签（回车跳过）：').strip() or args.label
        except EOFError:
            pass
    binary = ensure_core(args.mihomo)
    before = selections(client.get('/proxies')['proxies'])
    rows, regions = [], {}
    gemini = None if args.no_gemini else {}
    # Use opaque internal names for joining, redact only at the reporting boundary.
    target_names = [name for name, _ in targets]
    print('测试 %d 个节点，%d 轮 × %d 个目标，延迟 %d 个 worker 并行、带宽串行；所有客户端访问均为 GET。' % (len(nodes), args.rounds, len(targets), args.jobs))
    if gemini is not None:
        print('每个节点另做一次匿名 Gemini 可用性检测（约 150 KiB 压缩页面；未判定的下一轮重试，--no-gemini 跳过）。')
    if not args.quick:
        print('预计最大下载载荷：%d MiB（节点数 × 8 + min(3, 节点数) × 32）；另有延迟/trace/协议开销。' % (len(nodes) * 8 + min(3, len(nodes)) * 32))
    tty = sys.stdout.isatty()

    def record(name, node_type, phase, round_no, target, kind, sample):
        row = dict(sample, time=dt.datetime.now().astimezone().isoformat(timespec='seconds'),
                   node=name, node_type=node_type, phase=phase, round=round_no, target=target, kind=kind, mbps=None)
        if kind == 'warm' and sample['connects']:
            row['note'] += ('；' if row['note'] else '') + '第二次请求新建连接，未复用'
        if kind == 'bw':
            row['mbps'] = bandwidth(sample)
            if row['mbps'] is None:
                row['note'] += ('；' if row['note'] else '') + '带宽不可信（需200、正常/超时、>=256KiB及正传输时长）'
        rows.append(row)

    after = None
    try:
        with PrivateCore(binary, source, args.jobs) as core:
            missing = [name for name, _ in nodes if name not in core.available]
            if missing:
                raise UserError('私有 provider 缺少 %d 个待测节点；请检查配置是否使用内联 proxies。' % len(missing))
            measure_latency(core, nodes, targets, args.rounds, args.timeout, record, regions, tty, gemini)
            for name, node_type in nodes:
                if gemini is not None and name in gemini:
                    check = gemini[name]
                    sample = dict(check['sample'])
                    sample['note'] = ('；'.join(filter(None, ['Gemini ' + gemini_label(check), sample['note']])))
                    record(name, node_type, 'gemini', check['round'], 'gemini', 'check', sample)
            port = core.config['listeners'][0]['port']
            if not args.quick:
                candidates = [item for item in rank_nodes(nodes, rows, target_names, args.min_mbps, regions=regions) if not item['reasons']]
                for index, item in enumerate(candidates, 1):
                    print(('\r' if tty else '') + '带宽初筛：%d/%d' % (index, len(candidates)), end='' if tty else '\n', flush=True)
                    core.select(item['node'])
                    sample = curl_measure(port, BW_URL.format(8 * 1024 * 1024), 5, max_bytes=8 * 1024 * 1024, limit_rate=args.limit_rate)[0]
                    record(item['node'], item['type'], 'bw1', 1, 'cloudflare-download', 'bw', sample)
                if tty:
                    print()
                screened = sorted((row for row in rows if row['phase'] == 'bw1' and row['mbps'] is not None), key=lambda row: row['mbps'], reverse=True)[:3]
                for index, row in enumerate(screened, 1):
                    print(('\r' if tty else '') + '带宽深测：%d/%d' % (index, len(screened)),
                          end='' if tty else '\n', flush=True)
                    core.select(row['node'])
                    sample = curl_measure(port, BW_URL.format(32 * 1024 * 1024), 10, max_bytes=32 * 1024 * 1024, limit_rate=args.limit_rate)[0]
                    record(row['node'], row['node_type'], 'bw2', 1, 'cloudflare-download', 'bw', sample)
                if tty and screened:
                    print()
    finally:
        try:
            after = selections(client.get('/proxies')['proxies'])
        except UserError:
            pass
    # Scrub all report fields (including node names) before formatting or writing.
    public_nodes = [(public_name(name), public(kind)) for name, kind in nodes]
    if len({name for name, _ in public_nodes}) != len(public_nodes):
        public_nodes = [(public_name(name) + ' [%d]' % (i + 1), public(kind)) for i, (name, kind) in enumerate(nodes)]
    mapping = {name: public_nodes[i][0] for i, (name, _) in enumerate(nodes)}
    for row in rows:
        row['node'] = mapping[row['node']]
        # Fixed phase/kind identifiers never originate in the source config.
        # Apply display redaction exactly once; short secrets need not be idempotent.
        for key in ('target', 'node_type', 'note'):
            row[key] = public(row[key])
    clean_targets = [public(name) for name in target_names]
    if len(set(clean_targets)) != len(clean_targets):
        raise UserError('目标名称脱敏后重复；请使用不包含地址或凭据的唯一名称。')
    ranking = rank_nodes(public_nodes, rows, clean_targets, args.min_mbps, args.quick,
                         # Infer from the original name before it is replaced for display.
                         {mapping[name]: regions.get(name) or region_name(name) for name, _ in nodes},
                         {mapping[name]: check for name, check in gemini.items()} if gemini is not None else None)
    summary = make_summary(ranking, clean_targets, [public_name(name) for name in skipped],
                           # Snapshot keys are always group names (selections() keeps groups only).
                           {public(k): public_name(v) for k, v in before.items()},
                           {public(k): public_name(v) for k, v in after.items()} if after is not None else None,
                           args.quick, args.min_mbps,
                           [public(name) for name in sorted(set(before) | set(after))
                            if before.get(name) != after.get(name)] if after is not None else None)
    host, label, group = public(socket.gethostname()), public(args.label), public(args.group)
    summary = '主机：%s  标签：%s  策略组：%s\n' % (host, label or '-', group) + summary
    print(summary)
    paths = write_results(args.out, host, label, group, rows, summary)
    print('已保存：' + '、'.join(path.name for path in paths))
    print('实际总用时：%.1f 秒' % (time.monotonic() - started))


def main(argv=None):
    args = parser().parse_args(argv)
    old_handlers = {}

    def interrupt(signum, frame):
        # Ignore further termination requests during cleanup.
        for sig in old_handlers:
            signal.signal(sig, signal.SIG_IGN)
        raise Interrupted()

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old_handlers[sig] = signal.signal(sig, interrupt)
    try:
        run(args)
        return 0
    except (KeyboardInterrupt, Interrupted):
        print('\n已中断')
        return 130
    except UserError as error:
        print('错误：' + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Exceptions may embed configuration paths or credentials: never print them.
        print('错误：本地文件、子进程或控制器响应异常；已清理私有实例。', file=sys.stderr)
        return 1
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    sys.exit(main())
