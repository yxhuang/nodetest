# nodetest

Compare latency, TLS/proxy setup, request reliability and download bandwidth of
nodes in a Clash group on your current WSL/Linux network. Python 3.8+ and curl
8.5+ are required; Python uses only the standard library.

nodetest copies your client's generated config into a private directory and
starts its own mihomo with random loopback listener ports and a random controller secret.
Each worker owns one selector group and its bound listener; unbound traffic is
rejected and there is no general-purpose main proxy port.
Only this private instance is switched. The running client's controller receives
GET requests only; all group selections are compared before and after testing.
Automatic groups can still change their own selection during a run.

## Safety

- Targets whose hostname contains `claude` or `anthropic` are rejected, as are
  non-ASCII hostnames. Requests do not follow redirects, expand URL globs, load
  curl configuration, or send cookies.
- Credentials are read locally at runtime, never included in reports. Temporary
  config/log files have mode 0600 in a 0700 directory, removed on normal exit,
  errors, Ctrl+C, SIGTERM and SIGHUP. On Linux a parent-death signal also kills
  the private core if Python dies. SIGKILL/power loss cannot run directory cleanup;
  remove abandoned `nodetest-*` directories in your temporary directory yourself.
- Tests explicitly use the private proxy and clear proxy environment variables.
  Kernel downloads may use your normal environment proxy.
- Node names and other report fields are scrubbed of credential values found in
  the config (values shorter than 4 characters are not searched). If a credential
  uses YAML the scanner cannot parse (e.g. block scalars), node names are replaced
  with `节点#N` for the whole report.
- Reports contain node names, machine name, location label and Cloudflare trace
  countries (common ISO codes are displayed in Chinese), never raw exit IPs.
  Review reports before sharing them.

## Install

```sh
git clone https://github.com/yxhuang/nodetest.git
cd nodetest
./install.sh
nodetest --help
```

Ensure `~/.local/bin` is on your login shell PATH. The installer creates an
idempotent symlink and optionally copies the Windows launcher:

```sh
./install.sh --cmd-dir /mnt/c/Users/Example/Desktop
```

Double-click `nodetest.cmd` to run in the default WSL distribution and ask for a
location label. Optionally set Windows `NODETEST_DISTRO` to a distribution name.
Arguments are forwarded, for example `nodetest.cmd --quick --rounds 2`.
The launcher pauses at exit. It requires WSL and a working login shell PATH;
its Windows execution must be verified on your own installation.

Enable the client's loopback external controller first. The default config
search uses `%APPDATA%/com.follow/clash/config.yaml` when available, then
`/mnt/c/Users/*/AppData/Roaming/com.follow/clash/config.yaml` (first sorted match).
For multiple Windows profiles, specify the config explicitly.

## Usage

```sh
nodetest --list-groups
nodetest --group AI专用 --label home
nodetest --quick --rounds 2
nodetest --quick --rounds 1 --jobs 4
nodetest --quick --no-gemini
nodetest --config /path/to/config.yaml --mihomo /path/to/mihomo
nodetest --target google=https://www.google.com/generate_204 --timeout 8
nodetest --limit-rate 2M --min-mbps 10 --out ./results
```

Defaults: 3 rounds, 8 seconds per latency request, 4 parallel latency workers
(`--jobs 1` through `--jobs 8`), Google/Cloudflare/ChatGPT
anonymous targets, output to `~/nettest/results`. Repeated `--target NAME=URL`
replaces the default target list. Only HTTP(S) targets without URL credentials
are accepted. Controller overrides use `--controller` and `--secret`; prefer
reading the secret from config to avoid shell history exposure.

Linux amd64 automatically downloads pinned mihomo **v1.19.32**, verifies the
compressed artifact's SHA-256 and installs it atomically in
`${XDG_CACHE_HOME:-~/.cache}/nodetest/mihomo-v1.19.32`.
Other architectures require `--mihomo`. No system proxy settings are modified.

## Reading results

The terminal and `summary.txt` show cold/reused request median TTFB per target,
cold-request p95, failure rate, bandwidth, elimination reasons and recommendations.
`raw.csv` uses UTF-8 with BOM and includes per-request HTTP status, appconnect,
TTFB, total duration, bytes, speed and failure/reconnection notes.
Names are filename-sanitized; repeated runs in the same minute get a suffix.

Within each round, nodes are distributed across workers with independent groups
and ports. All workers finish before the next round; node order rotates each
round to vary measurement timing. Bandwidth screening and deep tests always run
serially through T1 / the first listener, to avoid competing downloads.
Each target is requested twice in one
curl process. A server can close its connection; the second request is marked
when it creates a new connection. QUIC node sessions may survive between curl
processes, so “cold” does not always include a fresh node handshake.
`time_connect` measures the local proxy; appconnect includes proxy setup and
remote TLS; TTFB includes server response time. Any HTTP response counts as a
latency success, including 403/429, which do not imply service usability.
Country trace requests retry in later rounds until a country code is obtained.
Known codes and node-name inference use the same Chinese country names; unknown
codes remain unchanged.

Each node also gets one anonymous Gemini availability check: a GET of
`https://gemini.google.com/app` (no cookies, no redirects, compressed, capped
at 4 MiB) reads the per-IP availability flag and Google's country guess (ISO
alpha-3) from the page. The `Gemini` column shows 可用 / 不可用 / 未知 with that
country, e.g. `不可用(SGP)`. A supported country marked unavailable usually means
Google restricts that exit IP; `CHN` means Google geolocates the exit to China.
未知 (request failed, non-200, or the flag is missing after a page redesign) is
retried in later rounds. EEA/UK exits get a cookie-consent gate whose flag is
always false for anonymous visitors; these show `未知(…·需同意页)` and are not
retried. Gemini results do not
eliminate or reorder nodes; the summary instead lists recommended nodes that
also support Gemini, and nodes that pass the speed bar but cannot use Gemini.
`--no-gemini` skips the check. The flag is an undocumented page detail and may
change; verify 未知 results in a browser. The CSV stores one `phase=gemini`,
`kind=check` row per node with the verdict in `note`.

Measured on one machine with 23 nodes: one serial quick round took about
5.5 minutes; the default run (3 rounds, 4 workers, plus bandwidth) took about
6 minutes. Slow or failing nodes, shared network capacity and timeouts change
this. Actual total elapsed time is printed at completion. Parallel latency probes can influence one another on a
congested link; use `--jobs 1` for a serial comparison.

Nodes with >20% failed requests or any entirely failed target are eliminated.
Others rank by reaching the bandwidth threshold (default 10 Mbps), then the
mean of target cold TTFB medians, then pooled cold TTFB p95 (nearest rank).
The deep-test speed (32 MiB) determines qualification when available, otherwise
the screening speed (8 MiB).
Quick mode ranks on latency only. With no bandwidth-qualified candidate,
normal mode reports no fixed-node recommendation. Regional winners use the
same ranking among latency-eligible nodes; inspect their bandwidth status.

A single run cannot establish long-term stability. Repeat at different times.
URLTest may switch when a fixed node fails; to pin a node, select that concrete
node in an upper Selector group yourself.

## Traffic and limitations

Bandwidth screening downloads at most 8 MiB / 5 s per eligible node; the three
fastest trustworthy results get up to 32 MiB / 10 s each. The upper download
payload estimate is printed before testing: `nodes × 8 + min(3, nodes) × 32` MiB.
Latency responses, one small country-code trace and one Gemini page (about
150 KiB compressed) per node, and protocol overhead
are additional. `--quick` skips bandwidth, and `--limit-rate` caps bandwidth
requests. Timeouts retain partial download speed only with HTTP 200 and at least
256 KiB, using bytes / (total - TTFB). Small files favor nodes that ramp up quickly.

Only generated YAML configs with inline `proxies` are supported; remote proxy
providers are unsupported. Controller metadata is scanned by line, with no YAML
dependency. This is a direct-member test: nested groups, DIRECT and REJECT are
skipped. Private ports are selected dynamically; a bind race causes a clean
startup failure. WSL networking/firewall restrictions can prevent UDP nodes from
working; a failure is not proof the node itself is bad. The tool does not check
account access or log in to any target service; the Gemini check reflects
anonymous region/IP availability only.

## Tests

```sh
python3 -m py_compile nodetest.py
python3 -m unittest discover -s tests -q
```

Tests use synthetic configurations and mocked subprocesses/controllers, without
network access or a real mihomo process.

## License

MIT, see [LICENSE](LICENSE).
