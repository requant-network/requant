"""A Lightning regtest world for the swap tests: bitcoind -regtest and LND nodes with REST on plain HTTP.

    from lnreg import World
    w = World(tmp, bitcoind_path, lnd_path); maker, payer = w.lnd('maker'), w.lnd('payer')
    w.channel(payer, maker, 1_000_000)
"""
import base64
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait(what, f, secs=120):
    t = time.time()
    while True:
        try:
            v = f()
        except Exception:
            v = None
        if v:
            return v
        if time.time() - t > secs:
            raise AssertionError('timed out waiting for ' + what)
        time.sleep(0.3)


class Bitcoind:
    def __init__(self, tmp, binary):
        os.makedirs(tmp, exist_ok=True)
        self.port = free_port()
        self.proc = subprocess.Popen([binary, '-regtest', '-server', '-listen=0', '-txindex', '-fallbackfee=0.0001',
                                      f'-datadir={tmp}', f'-rpcport={self.port}', f'-port={free_port()}',
                                      '-rpcuser=u', '-rpcpassword=p'], stdout=subprocess.DEVNULL)
        wait('bitcoind', lambda: self.call('getblockchaininfo'))
        self.call('createwallet', ['w'])
        self.addr = self.call('getnewaddress')
        self.mine(101)

    def call(self, method, params=None):
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': params or []}).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}', body, {'Authorization': 'Basic dTpw'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())['result']
        except urllib.error.HTTPError as e:
            raise RuntimeError(json.loads(e.read())['error']['message'])

    def mine(self, n=1):
        return self.call('generatetoaddress', [n, self.addr])

    def stop(self):
        try:
            self.call('stop')
            self.proc.wait(30)
        except Exception:
            self.proc.kill()


class Lnd:
    def __init__(self, name, tmp, binary, btc):
        self.name, self.dir = name, os.path.join(tmp, name)
        self.rest, self.p2p, self.rpc = free_port(), free_port(), free_port()
        self.proc = subprocess.Popen([binary, '--bitcoin.regtest', '--bitcoin.node=bitcoind', f'--lnddir={self.dir}',
                                      f'--bitcoind.rpchost=127.0.0.1:{btc.port}', '--bitcoind.rpcuser=u',
                                      '--bitcoind.rpcpass=p', '--bitcoind.rpcpolling', '--noseedbackup',
                                      f'--listen=127.0.0.1:{self.p2p}', f'--rpclisten=127.0.0.1:{self.rpc}',
                                      f'--restlisten=127.0.0.1:{self.rest}', '--no-rest-tls', '--trickledelay=50',
                                      '--alias=' + name, '--debuglevel=warn'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.macaroon_path = os.path.join(self.dir, 'data', 'chain', 'bitcoin', 'regtest', 'admin.macaroon')
        wait(name + ' macaroon', lambda: os.path.isfile(self.macaroon_path), 120)
        self.macaroon = open(self.macaroon_path, 'rb').read().hex()
        wait(name + ' synced', lambda: self.get('/v1/getinfo')['synced_to_chain'], 120)
        self.pubkey = self.get('/v1/getinfo')['identity_pubkey']

    def req(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(f'http://127.0.0.1:{self.rest}{path}', data, method=method,
                                   headers={'Grpc-Metadata-macaroon': self.macaroon})
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                text = resp.read().decode()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f'{self.name} {path}: {e.read().decode()[:300]}')
        # streaming endpoints answer one JSON object per line
        lines = [json.loads(l) for l in text.splitlines() if l.strip()]
        last = lines[-1] if lines else {}
        return last.get('result', last) if isinstance(last, dict) and set(last) <= {'result', 'error'} and 'result' in last else last

    def get(self, path):
        return self.req('GET', path)

    def post(self, path, body, timeout=60):
        return self.req('POST', path, body, timeout)

    def stop(self):
        try:
            self.post('/v1/stop', {})
            self.proc.wait(30)
        except Exception:
            self.proc.kill()


class World:
    def __init__(self, tmp, bitcoind, lnd):
        self.tmp, self.lnd_bin = tmp, lnd
        self.btc = Bitcoind(os.path.join(tmp, 'btc'), bitcoind)
        self.nodes = []

    def lnd(self, name):
        n = Lnd(name, self.tmp, self.lnd_bin, self.btc)
        self.nodes.append(n)
        return n

    def fund(self, node, btc=1.0):
        addr = node.get('/v1/newaddress?type=0')['address']
        self.btc.call('sendtoaddress', [addr, btc])
        self.btc.mine(6)
        wait(node.name + ' funds', lambda: int(node.get('/v1/balance/blockchain').get('confirmed_balance', 0)) > 0)

    def channel(self, a, b, sats):
        """A channel from a to b of `sats` (a holds the liquidity), active."""
        self.fund(a)
        a.post('/v1/peers', {'addr': {'pubkey': b.pubkey, 'host': f'127.0.0.1:{b.p2p}'}, 'perm': False})
        a.post('/v1/channels', {'node_pubkey': base64.b64encode(bytes.fromhex(b.pubkey)).decode(),
                                'local_funding_amount': str(sats)})
        self.btc.mine(6)
        wait('the channel', lambda: any(c.get('active') for c in a.get('/v1/channels').get('channels', [])), 120)
        # an active channel takes a few seconds more before it carries payments
        time.sleep(5)

    def pay_async(self, payer, bolt11, timeout=120):
        """Pay in a thread (a held invoice blocks the call); returns a dict that gets the final status."""
        result = {}

        def run():
            try:
                result['status'] = payer.post('/v2/router/send', {'payment_request': bolt11, 'timeout_seconds': timeout,
                                                                   'fee_limit_sat': '1000'}, timeout=timeout + 30)
            except Exception as e:
                result['error'] = str(e)
        threading.Thread(target=run, daemon=True).start()
        return result

    def stop(self):
        for n in self.nodes:
            n.stop()
        self.btc.stop()
