"""RQT<->BTC atomic swaps end to end on two regtest chains: requantd and bitcoind, with requant-maker and
requant-wallet (the taker). Skipped unless BITCOIND names a bitcoind binary and the release binaries are
built (`cargo build --release -p requant-node -p requant-wallet`).

Scenarios: a swap that completes; an underpaid one and one paid after the funding window (the taker
takes the BTC back after the timeout); one the taker never claims (the maker takes the RQT back, the
taker the BTC).
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from decimal import Decimal

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = ".exe" if os.name == "nt" else ""
REL = os.path.join(ROOT, "target", "release")
NODE, WALLET, MAKER = (os.path.join(REL, n + EXE) for n in ("requantd", "requant-wallet", "requant-maker"))
BITCOIND = os.environ.get("BITCOIND", "")

pytestmark = pytest.mark.skipif(
    not (BITCOIND and os.path.isfile(BITCOIND) and all(os.path.isfile(p) for p in (NODE, WALLET, MAKER))),
    reason="BITCOIND and the release binaries are needed",
)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait(what, f, secs=180):
    t = time.time()
    while True:
        v = f()
        if v:
            return v
        if time.time() - t > secs:
            raise AssertionError("timed out waiting for " + what)
        time.sleep(0.3)


class Btc:
    def __init__(self, tmp):
        os.makedirs(tmp, exist_ok=True)
        self.port = free_port()
        self.proc = subprocess.Popen([BITCOIND, "-regtest", "-server", "-listen=0", "-txindex", "-fallbackfee=0.0001",
                                      f"-datadir={tmp}", f"-rpcport={self.port}", f"-port={free_port()}",
                                      "-rpcuser=u", "-rpcpassword=p"], stdout=subprocess.DEVNULL)
        wait("bitcoind", lambda: self.proc.poll() is not None and pytest.fail("bitcoind exited") or self.ok("getblockchaininfo"))
        self.call("createwallet", ["w"])
        self.miner = self.call("getnewaddress")
        self.mine(101)

    def call(self, method, params=None):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}", body, {"Authorization": "Basic dTpw"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())["result"]
        except urllib.error.HTTPError as e:
            raise RuntimeError(json.loads(e.read())["error"]["message"])

    def ok(self, method):
        try:
            self.call(method)
            return True
        except Exception:
            return False

    def mine(self, n):
        self.call("generatetoaddress", [n, self.miner])

    def height(self):
        return self.call("getblockcount")

    def received(self, address):
        return sum(round(Decimal(str(u["amount"])) * 10**8)
                   for u in self.call("scantxoutset", ["start", [f"addr({address})"]])["unspents"])

    def stop(self):
        try:
            self.call("stop")
            self.proc.wait(20)
        except Exception:
            self.proc.kill()


@pytest.fixture(scope="module")
def world():
    tmp = tempfile.mkdtemp(prefix="rq-swap-")
    btc = Btc(os.path.join(tmp, "btc"))
    api_port = free_port()
    api = f"http://127.0.0.1:{api_port}"

    def wallet(*args, check=True):
        done = subprocess.run([WALLET, *args, "--network", "regtest", "--api", api, "--yes"], cwd=tmp,
                              capture_output=True, text=True, timeout=120)
        if check and done.returncode:
            raise AssertionError(f"{args}: {done.stderr.strip()}")
        return done

    def field(out, name):
        return next(line.split()[-1] for line in out.splitlines() if line.startswith(name))

    miner = wallet("keygen", "miner.key", "--no-passphrase").stdout
    for k in ("maker.key", "taker.key"):
        wallet("keygen", k, "--no-passphrase")
    node = subprocess.Popen([NODE, "--network", "regtest", "--datadir", os.path.join(tmp, "node"), "--listen",
                             f"127.0.0.1:{free_port()}", "--rpc", f"127.0.0.1:{free_port()}", "--explorer",
                             f"127.0.0.1:{api_port}", "--mine", field(miner, "key hash"), "--mine-interval-ms", "60",
                             "--no-discover"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def balance(src):
        out = wallet("balance", src).stdout
        return round(Decimal(next(l for l in out.splitlines() if l.startswith("confirmed")).split()[1]) * 10**8)

    def rqt_height():
        with urllib.request.urlopen(api + "/api/info", timeout=10) as r:
            return json.loads(r.read())["height"]

    wait("the Requant API", lambda: subprocess.run([WALLET, "balance", "miner.key", "--network", "regtest", "--api", api],
                                                   cwd=tmp, capture_output=True).returncode == 0)
    wait("mature coins", lambda: balance("miner.key") > 200 * 10**8)
    maker_addr = field(wallet("address", "maker.key").stdout, "address")
    wallet("send", "miner.key", maker_addr, "100")
    wait("the maker's RQT", lambda: balance("maker.key") >= 100 * 10**8)
    subprocess.run([MAKER, "btc-keygen", "maker-btc.key"], cwd=tmp, check=True, capture_output=True)
    with open(os.path.join(tmp, "bitcoind.auth"), "w") as f:
        f.write("u:p")
    maker_port = free_port()
    payout = btc.call("getnewaddress")
    cfg = {"rqt_network": "regtest", "rqt_api": api, "rqt_key": "maker.key", "btc_network": "regtest",
           "bitcoind": f"127.0.0.1:{btc.port}", "bitcoind_auth": "bitcoind.auth", "btc_key": "maker-btc.key",
           "btc_payout": payout, "sats_per_rqt": 1000, "min_rqt": 10**7, "max_rqt": 50 * 10**8,
           "listen": f"127.0.0.1:{maker_port}", "state": "maker-state.json", "tick_seconds": 1}
    with open(os.path.join(tmp, "maker.json"), "w") as f:
        json.dump(cfg, f)
    log = open(os.path.join(tmp, "maker.log"), "w")
    maker = subprocess.Popen([MAKER, "run", "maker.json"], cwd=tmp, stdout=log, stderr=log)
    w = dict(tmp=tmp, btc=btc, wallet=wallet, balance=balance, rqt_height=rqt_height, maker=f"127.0.0.1:{maker_port}",
             payout=payout)
    wait("the maker", lambda: subprocess.run([WALLET, "swap", "status", "none"], cwd=tmp, capture_output=True) is not None)
    time.sleep(1)
    yield w
    maker.kill()
    node.terminate()
    node.wait(20)
    btc.stop()
    log.close()
    shutil.rmtree(tmp, ignore_errors=True)


def buy(w, name, amount):
    out = w["wallet"]("swap", "buy", w["maker"], amount, "taker.key", "--out", name).stdout
    lines = dict(l.split(None, 1) for l in out.splitlines())
    sats = int(lines["pay"].split("(")[1].split()[0])
    return lines["to"].strip(), sats


def status(w, name):
    return json.loads(w["wallet"]("swap", "status", name).stdout)


def test_a_swap_completes(world):
    w, btc = world, world["btc"]
    before = w["balance"]("taker.key")
    address, sats = buy(w, "s1.json", "2")
    assert sats == 2000
    # a second swap with the same secret is refused by the maker; the taker never pays a forged address
    btc.call("sendtoaddress", [address, sats / 1e8])
    btc.mine(1)
    st = wait("the RQT lock", lambda: (s := status(w, "s1.json"))["state"] == "rqt_locked" and s)
    assert st["rqt_htlc"]["claim"] and st["funding"]["sats"] == sats
    wait("the lock to confirm", lambda: w["wallet"]("swap", "claim", "s1.json", "taker.key", check=False).returncode == 0)
    wait("the RQT at the taker", lambda: w["balance"]("taker.key") > before + 199 * 10**6)
    wait("the maker's BTC claim", lambda: status(w, "s1.json")["state"] in ("btc_claimed", "done"))
    btc.mine(1)
    wait("the swap to finish", lambda: status(w, "s1.json")["state"] == "done")
    assert btc.received(w["payout"]) > sats - 1000


def refund_btc(w, name, address):
    """After the Bitcoin timeout, the taker's refund is accepted (and refused before it)."""
    btc = w["btc"]
    unspent = btc.call("scantxoutset", ["start", [f"addr({address})"]])["unspents"][0]
    sats = round(Decimal(str(unspent["amount"])) * 10**8)
    to = btc.call("getnewaddress")
    args = ["swap", "refund", name, to, "--txid", unspent["txid"], "--vout", str(unspent["vout"]), "--sats", str(sats)]
    tx = w["wallet"](*args).stdout.strip()
    with pytest.raises(RuntimeError, match="non-final"):
        btc.call("sendrawtransaction", [tx])
    timeout = json.load(open(os.path.join(w["tmp"], name)))["btc_htlc"]["timeout"]
    btc.mine(timeout - btc.height())
    btc.call("sendrawtransaction", [tx])
    btc.mine(1)
    assert btc.received(to) > sats - 1000


def test_underpaid_and_late_swaps_are_refunded_to_the_taker(world):
    w, btc = world, world["btc"]
    address, sats = buy(w, "s2.json", "1")
    btc.call("sendtoaddress", [address, (sats - 1) / 1e8])
    btc.mine(1)
    wait("underpaid", lambda: status(w, "s2.json")["state"] == "underpaid")
    refund_btc(w, "s2.json", address)
    # paid after the funding window: the swap expired, the maker never locks
    address, sats = buy(w, "s3.json", "1")
    btc.mine(13)
    wait("expired", lambda: status(w, "s3.json")["state"] == "expired")
    btc.call("sendtoaddress", [address, sats / 1e8])
    btc.mine(1)
    time.sleep(3)
    assert status(w, "s3.json")["state"] == "expired"
    refund_btc(w, "s3.json", address)


def test_a_swap_the_taker_never_claims(world):
    w, btc = world, world["btc"]
    address, sats = buy(w, "s4.json", "1")
    btc.call("sendtoaddress", [address, sats / 1e8])
    btc.mine(1)
    st = wait("the RQT lock", lambda: (s := status(w, "s4.json"))["state"] == "rqt_locked" and s)
    # the taker does nothing: at the Requant timeout the maker takes its RQT back
    timeout = st["rqt_htlc"]["timeout"]
    wait("the Requant timeout", lambda: w["rqt_height"]() >= timeout, secs=240)
    wait("the maker's refund", lambda: status(w, "s4.json")["state"] == "rqt_refunded", secs=120)
    # a claim is now impossible, and the taker takes the BTC back after the Bitcoin timeout
    assert w["wallet"]("swap", "claim", "s4.json", "taker.key", check=False).returncode != 0
    refund_btc(w, "s4.json", address)
