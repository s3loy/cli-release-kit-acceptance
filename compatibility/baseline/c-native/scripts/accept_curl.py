from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64, errno, hashlib, json, socket, ssl, subprocess, sys, threading, time, os, signal

CHECK_STARTED = time.monotonic()
CHECK_DEADLINE = CHECK_STARTED + 300
ACTIVE_PROCESS = None

BASE = Path(sys.argv[2]).resolve()
BASE.mkdir(parents=True, exist_ok=True)
(BASE / 'logs').mkdir(exist_ok=True)
EXE = Path(sys.argv[1]).resolve()
RESULT = BASE / 'functional.json'
BODY = b'official curl local acceptance\n'
BINARY = bytes(range(256)) * 32
records = []
EXEC_PREFIX = json.loads(os.environ.get('CURL_EXEC_PREFIX_JSON', '[]'))
assert isinstance(EXEC_PREFIX, list) and all(isinstance(arg, str) for arg in EXEC_PREFIX)


def whole_process_deadline(signum, frame):
    if ACTIVE_PROCESS is not None:
        try:
            os.killpg(ACTIVE_PROCESS.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    report = {'scope': 'isolated Linux baseline manual CMake control; not a relship receipt',
              'status': 'whole-process-deadline-exceeded', 'deadline_seconds': 300,
              'seconds': round(time.monotonic() - CHECK_STARTED, 3),
              'completed': len(records), 'total': 12, 'passed': sum(row['passed'] for row in records),
              'commands': records, 'execution_prefix': EXEC_PREFIX,
              'active_command_logs': globals().get('ACTIVE_LOGS')}
    try:
        RESULT.write_text(json.dumps(report, indent=2)+'\n')
    finally:
        os._exit(124)


signal.signal(signal.SIGALRM, whole_process_deadline)
signal.setitimer(signal.ITIMER_REAL, max(0.001, CHECK_DEADLINE - time.monotonic()))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def reply(self, status, body, headers=None, head=False):
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Local-Fixture', 'curl-consumer-20261117')
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if not head:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
    def do_HEAD(self):
        self.reply(200, BODY, head=True)
    def do_GET(self):
        if self.path == '/ok':
            self.reply(200, BODY, {'Content-Type': 'text/plain'})
        elif self.path == '/redirect':
            self.reply(302, b'', {'Location': '/ok'})
        elif self.path == '/missing':
            self.reply(404, b'fixture missing\n')
        elif self.path == '/slow':
            time.sleep(0.7)
            self.reply(200, BODY)
        elif self.path == '/binary':
            if self.headers.get('Range') == 'bytes=128-255':
                self.reply(206, BINARY[128:256], {'Content-Range': f'bytes 128-255/{len(BINARY)}'})
            else:
                self.reply(200, BINARY, {'Content-Type': 'application/octet-stream'})
        else:
            self.reply(400, b'unknown fixture path')
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        value = {'body_base64': base64.b64encode(body).decode(), 'content_type': self.headers.get('Content-Type'), 'custom_header': self.headers.get('X-Consumer-Test')}
        self.reply(200, json.dumps(value, sort_keys=True).encode(), {'Content-Type': 'application/json'})


def run(name, options, expected_code=0, check=None):
    global ACTIVE_PROCESS, ACTIVE_LOGS
    argv = EXEC_PREFIX + [str(EXE), '--disable', '--noproxy', '*', '--silent', '--show-error', '--max-time', '5'] + options
    started = time.monotonic()
    timed_out = False
    assertion_error = None
    stdout_path = BASE / 'logs' / (name + '.stdout')
    stderr_path = BASE / 'logs' / (name + '.stderr')
    ACTIVE_LOGS = {'stdout': str(stdout_path), 'stderr': str(stderr_path)}
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        ACTIVE_PROCESS = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = ACTIVE_PROCESS.wait(timeout=max(0.001, min(20, CHECK_DEADLINE - time.monotonic())))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(ACTIVE_PROCESS.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = ACTIVE_PROCESS.wait()
        finally:
            ACTIVE_PROCESS = None
    p = subprocess.CompletedProcess(argv, code, stdout_path.read_bytes(), stderr_path.read_bytes())
    ok = p.returncode == expected_code
    if check is not None:
        try:
            ok = bool(check(p)) and ok
        except Exception as error:
            ok = False
            assertion_error = repr(error)
    row = {'name': name, 'argv': argv, 'expected_exit_code': expected_code, 'actual_exit_code': p.returncode, 'passed': ok and not timed_out, 'timed_out': timed_out, 'assertion_error': assertion_error, 'seconds': round(time.monotonic() - started, 3), 'stdout': 'logs/' + name + '.stdout', 'stderr': 'logs/' + name + '.stderr', 'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(p.stderr).hexdigest()}
    records.append(row)
    print(name, 'PASS' if ok else 'FAIL', p.returncode, flush=True)
    return p

certdir = Path(sys.argv[3]).resolve()
assert (certdir / 'cert.pem').is_file() and (certdir / 'key.pem').is_file()
(BASE / 'tls-fixture').mkdir(exist_ok=True)

http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
https = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certdir/'cert.pem', certdir/'key.pem')
https.socket = context.wrap_socket(https.socket, server_side=True)
for server in [http, https]:
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
httpurl = f'http://127.0.0.1:{http.server_port}'
httpsurl = f'https://127.0.0.1:{https.server_port}'
try:
    run('manual-version', ['--version'], check=lambda p: b'curl 8.23.0' in p.stdout and b'https' in p.stdout and b'OpenSSL/3.5.9' in p.stdout)
    run('manual-get-body-headers', ['--dump-header', str(BASE/'logs/manual-get.headers'), httpurl+'/ok'], check=lambda p: p.stdout == BODY and 'X-Local-Fixture: curl-consumer-20261117' in (BASE/'logs/manual-get.headers').read_text())
    run('manual-head', ['--head', httpurl+'/ok'], check=lambda p: b'HTTP/1.0 200 OK' in p.stdout and b'Content-Length: '+str(len(BODY)).encode() in p.stdout)
    run('manual-redirect', ['--location', httpurl+'/redirect'], check=lambda p: p.stdout == BODY)
    payload = b'curl post payload \x00\xff'
    (BASE/'tls-fixture/post.bin').write_bytes(payload)
    run('manual-post', ['--header', 'X-Consumer-Test: accepted', '--header', 'Content-Type: application/octet-stream', '--data-binary', '@'+str(BASE/'tls-fixture/post.bin'), httpurl+'/post'], check=lambda p: json.loads(p.stdout) == {'body_base64': base64.b64encode(payload).decode(), 'content_type': 'application/octet-stream', 'custom_header': 'accepted'})
    run('manual-binary-download', ['--output', str(BASE/'tls-fixture/download.bin'), httpurl+'/binary'], check=lambda p: (BASE/'tls-fixture/download.bin').read_bytes() == BINARY)
    run('manual-range', ['--range', '128-255', httpurl+'/binary'], check=lambda p: p.stdout == BINARY[128:256])
    run('manual-http-failure', ['--fail-with-body', httpurl+'/missing'], expected_code=22, check=lambda p: p.stdout == b'fixture missing\n' and b'404' in p.stderr)
    run('manual-timeout', ['--max-time', '0.15', httpurl+'/slow'], expected_code=28, check=lambda p: b'timed out' in p.stderr)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        closed_port = reserved.getsockname()[1]
    with socket.socket() as native_probe:
        native_probe.settimeout(0.5)
        assert native_probe.connect_ex(('127.0.0.1', closed_port)) == errno.ECONNREFUSED
    run('manual-connection-refused', [f'http://127.0.0.1:{closed_port}/'], expected_code=7, check=lambda p: b'Failed to connect' in p.stderr)
    run('manual-https-untrusted', [httpsurl+'/ok'], expected_code=60, check=lambda p: b'certificate' in p.stderr.lower())
    run('manual-https-trusted', ['--cacert', str(certdir/'cert.pem'), httpsurl+'/ok'], check=lambda p: p.stdout == BODY)
finally:
    for server in [http, https]:
        server.shutdown()
        server.server_close()

report = {'scope': 'isolated Linux baseline manual CMake control; not a relship build or verification receipt', 'whole_process_deadline_seconds': 300, 'seconds': round(time.monotonic() - CHECK_STARTED, 3), 'execution_prefix': EXEC_PREFIX, 'executable': str(EXE), 'executable_sha256': hashlib.sha256(EXE.read_bytes()).hexdigest(), 'fixtures': {'http': httpurl, 'https': httpsurl, 'servers_closed': True, 'tls_ca_installed_in_system': False, 'certificate_sha256': hashlib.sha256((certdir/'cert.pem').read_bytes()).hexdigest(), 'python_version': sys.version, 'python_ssl': ssl.OPENSSL_VERSION}, 'passed': sum(x['passed'] for x in records), 'total': len(records), 'commands': records}
RESULT.write_text(json.dumps(report, indent=2)+'\n')
assert report['passed'] == report['total'], report
signal.setitimer(signal.ITIMER_REAL, 0)
