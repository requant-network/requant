"""RQT for BTC paid over Lightning, end to end on regtest: requantd, bitcoind and two LND nodes (the
maker's, and one standing for the taker's Lightning wallet). Skipped unless BITCOIND and LND name the
binaries and the release binaries are built.

Scenarios: a swap completes (the hold invoice is settled with the secret the taker's claim revealed);
the maker cannot lock the RQT (the invoice is cancelled and the payment goes back); the taker never
claims (the maker takes the RQT back and cancels, and the payment goes back).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from decimal import Decimal

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lnreg import World, free_port, wait  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = ".exe" if os.name == "nt" else ""
REL = os.path.join(ROOT, "target", "release")
NODE, WALLET, MAKER = (os.path.join(REL, n + EXE) for n in ("requantd", "requant-wallet", "requant-maker"))
BITCOIND, LND = os.environ.get("BITCOIND", ""), os.environ.get("LND", "")

pytestmark = pytest.mark.skipif(
    not (BITCOIND and LND and os.path.isfile(BITCOIND) and os.path.isfile(LND)
         and all(os.path.isfile(p) for p in (NODE, WALLET, MAKER))),
    reason="BITCOIND, LND and the release binaries are needed",
)


@pytest.fixture(scope="module")
def world():
    tmp = tempfile.mkdtemp(prefix="rq-ln-")
    w = World(tmp, BITCOIND, LND)
    maker_ln, payer = w.lnd("maker"), w.lnd("payer")
    w.channel(payer, maker_ln, 1_000_000)
    api_port = free_port()
    api = f"http://127.0.0.1:{api_port}"

    def wallet(*args, check=True):
        done = subprocess.run([WALLET, *args, "--network", "regtest", "--api", api, "--yes"], cwd=tmp,
                              capture_output=True, text=True, timeout=120)
        if check and done.returncode:
            raise AssertionError(f"{args}: {done.stderr.strip()}")
        return done

    field = lambda out, name: next(l.split()[-1] for l in out.splitlines() if l.startswith(name))
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

    wait("the Requant API", lambda: subprocess.run([WALLET, "balance", "miner.key", "--network", "regtest", "--api", api],
                                                   cwd=tmp, capture_output=True).returncode == 0)
    wait("mature coins", lambda: balance("miner.key") > 200 * 10**8, 180)
    wallet("send", "miner.key", field(wallet("address", "maker.key").stdout, "address"), "50")
    wait("the maker's RQT", lambda: balance("maker.key") >= 50 * 10**8)
    subprocess.run([MAKER, "btc-keygen", "maker-btc.key"], cwd=tmp, check=True, capture_output=True)
    with open(os.path.join(tmp, "bitcoind.auth"), "w") as f:
        f.write("u:p")
    port = free_port()
    cfg = {"rqt_network": "regtest", "rqt_api": api, "rqt_key": "maker.key", "btc_network": "regtest",
           "bitcoind": f"127.0.0.1:{w.btc.port}", "bitcoind_auth": "bitcoind.auth", "btc_key": "maker-btc.key",
           "btc_payout": w.btc.call("getnewaddress"), "sats_per_rqt": 1000, "min_rqt": 10**7, "max_rqt": 500 * 10**8,
           "lnd": {"rest": f"127.0.0.1:{maker_ln.rest}", "macaroon": maker_ln.macaroon_path},
           "listen": f"127.0.0.1:{port}", "state": "maker-state.json", "tick_seconds": 1}
    with open(os.path.join(tmp, "maker.json"), "w") as f:
        json.dump(cfg, f)
    log = open(os.path.join(tmp, "maker.log"), "w")
    maker = subprocess.Popen([MAKER, "run", "maker.json"], cwd=tmp, stdout=log, stderr=log)
    time.sleep(1.5)

    def rqt_height():
        with urllib.request.urlopen(api + "/api/info", timeout=10) as r:
            return json.loads(r.read())["height"]

    yield dict(tmp=tmp, w=w, payer=payer, maker_ln=maker_ln, wallet=wallet, balance=balance,
               maker=f"127.0.0.1:{port}", rqt_height=rqt_height)
    maker.kill()
    node.terminate()
    node.wait(20)
    w.stop()
    log.close()
    shutil.rmtree(tmp, ignore_errors=True)


def buy(world, name, amount):
    out = world["wallet"]("swap", "buy-ln", world["maker"], amount, "taker.key", "--out", name).stdout
    return next(l.split()[-1] for l in out.splitlines() if l.startswith("invoice"))


def status(world, name):
    return json.loads(world["wallet"]("swap", "status", name).stdout)


def test_a_lightning_swap_completes(world):
    before = world["balance"]("taker.key")
    bolt11 = buy(world, "l1.json", "2")
    paid = world["w"].pay_async(world["payer"], bolt11)
    wait("the RQT lock", lambda: status(world, "l1.json")["state"] == "rqt_locked", 60)
    assert "status" not in paid, "the payment is held until the secret is known"
    wait("the claim", lambda: world["wallet"]("swap", "claim", "l1.json", "taker.key", check=False).returncode == 0, 60)
    wait("the settlement", lambda: status(world, "l1.json")["state"] == "done", 60)
    wait("the payer's result", lambda: paid.get("status", {}).get("status") == "SUCCEEDED", 60)
    wait("the RQT at the taker", lambda: world["balance"]("taker.key") > before + 199 * 10**6)
    # a refund makes no sense for a Lightning swap
    assert world["wallet"]("swap", "refund", "l1.json", "x", check=False).returncode != 0


def test_a_lock_the_maker_cannot_make_goes_back(world):
    bolt11 = buy(world, "l2.json", "200")  # the maker holds only 50 RQT
    paid = world["w"].pay_async(world["payer"], bolt11)
    wait("the cancel", lambda: status(world, "l2.json")["state"] == "failed", 60)
    wait("the payment back", lambda: paid.get("status", {}).get("status") == "FAILED", 60)


def test_an_unclaimed_lightning_swap_goes_back_to_both(world):
    bolt11 = buy(world, "l3.json", "1")
    paid = world["w"].pay_async(world["payer"], bolt11)
    st = wait("the RQT lock", lambda: (s := status(world, "l3.json"))["state"] == "rqt_locked" and s, 60)
    timeout = st["rqt_htlc"]["timeout"]
    wait("the Requant timeout", lambda: world["rqt_height"]() >= timeout, 120)
    wait("the maker's refund", lambda: status(world, "l3.json")["state"] == "rqt_refunded", 120)
    wait("the payment back", lambda: paid.get("status", {}).get("status") == "FAILED", 60)
    assert world["wallet"]("swap", "claim", "l3.json", "taker.key", check=False).returncode != 0
