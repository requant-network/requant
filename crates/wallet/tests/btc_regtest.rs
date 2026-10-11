//! The Bitcoin HTLC of `requant_wallet::btc` against a real `bitcoind -regtest`:
//!
//!     BITCOIND=/path/to/bitcoind cargo test -p requant-wallet --test btc_regtest
//!
//! Without BITCOIND the test says so and passes (the unit tests in btc.rs still check the scripts).

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::{Address, Network, OutPoint, Transaction};
use requant_wallet::btc::{public_key, revealed_secret, Htlc, Path};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Bitcoind {
    child: Child,
    port: u16,
    dir: std::path::PathBuf,
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        let _ = self.call("stop", json!([]));
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(10) && self.child.try_wait().ok().flatten().is_none() {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Bitcoind {
    fn start(bin: &str) -> Bitcoind {
        let dir = std::env::temp_dir().join(format!("requant-btc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (port, p2p) = (free_port(), free_port());
        let child = Command::new(bin)
            .args([
                "-regtest",
                "-server",
                "-listen=0",
                "-txindex",
                "-fallbackfee=0.0001",
                &format!("-datadir={}", dir.display()),
                &format!("-rpcport={port}"),
                &format!("-port={p2p}"),
                "-rpcuser=u",
                "-rpcpassword=p",
            ])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let b = Bitcoind { child, port, dir };
        let t = Instant::now();
        while b.call("getblockchaininfo", json!([])).is_err() {
            assert!(t.elapsed() < Duration::from_secs(60), "bitcoind did not start");
            std::thread::sleep(Duration::from_millis(200));
        }
        b
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).map_err(|e| e.to_string())?;
        // u:p
        write!(
            s,
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dTpw\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .map_err(|e| e.to_string())?;
        let mut resp = String::new();
        s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
        let json = resp.split("\r\n\r\n").nth(1).ok_or("no body")?;
        let v: Value = serde_json::from_str(json).map_err(|e| format!("{e}: {json}"))?;
        if !v["error"].is_null() {
            return Err(v["error"]["message"].as_str().unwrap_or("error").to_string());
        }
        Ok(v["result"].clone())
    }

    fn mine(&self, n: u64, to: &str) {
        self.call("generatetoaddress", json!([n, to])).unwrap();
    }

    fn height(&self) -> u32 {
        self.call("getblockcount", json!([])).unwrap().as_u64().unwrap() as u32
    }

    /// Pay `sats` to `addr` from the node's wallet, mine it; the outpoint.
    fn fund(&self, addr: &Address, sats: u64, miner: &str) -> OutPoint {
        let txid = self.call("sendtoaddress", json!([addr.to_string(), sats as f64 / 1e8])).unwrap();
        self.mine(1, miner);
        let raw = self.call("getrawtransaction", json!([txid, true])).unwrap();
        let vout =
            raw["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["address"] == addr.to_string()).unwrap()
                ["n"]
                .as_u64()
                .unwrap() as u32;
        OutPoint { txid: txid.as_str().unwrap().parse().unwrap(), vout }
    }

    fn send(&self, tx: &Transaction) -> Result<Value, String> {
        self.call("sendrawtransaction", json!([serialize_hex(tx)]))
    }
}

#[test]
fn htlc_claim_and_refund_on_bitcoind_regtest() {
    let Ok(bin) = std::env::var("BITCOIND") else {
        eprintln!("BITCOIND not set: the regtest HTLC test is skipped");
        return;
    };
    let node = Bitcoind::start(&bin);
    node.call("createwallet", json!(["w"])).unwrap();
    let miner = node.call("getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
    node.mine(101, &miner);
    let secret = [0x5a; 32];
    let hash = bitcoin::hashes::sha256::Hash::hash(&secret).to_byte_array();
    let (maker, user) = ([3u8; 32], [4u8; 32]);
    let payout: Address = node
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .parse::<Address<_>>()
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();

    // the maker claims with the secret; the secret can be read back from the chain
    let h = Htlc {
        hash,
        claim: public_key(&maker).unwrap(),
        refund: public_key(&user).unwrap(),
        timeout: node.height() + 20,
    };
    let op = node.fund(&h.address(Network::Regtest), 1_000_000, &miner);
    // the wrong length of secret is refused by the script itself, whatever the hash
    let mut short = h.spend(op, 1_000_000, Path::Claim { preimage: secret }, &payout, 2, &maker).unwrap();
    let mut w: Vec<Vec<u8>> = short.input[0].witness.iter().map(|x| x.to_vec()).collect();
    w[1] = vec![0x5a; 31];
    short.input[0].witness = bitcoin::Witness::from_slice(&w);
    assert!(node.send(&short).is_err(), "a 31-byte secret must not open the HTLC");
    let claim = h.spend(op, 1_000_000, Path::Claim { preimage: secret }, &payout, 2, &maker).unwrap();
    let txid = node.send(&claim).unwrap();
    node.mine(1, &miner);
    let raw = node.call("getrawtransaction", json!([txid, false])).unwrap();
    let mined: Transaction = deserialize_hex(raw.as_str().unwrap()).unwrap();
    assert_eq!(revealed_secret(&mined, &h), Some(secret));

    // the user's refund: refused before the timeout, accepted from it
    let h2 = Htlc { timeout: node.height() + 10, ..h };
    let op2 = node.fund(&h2.address(Network::Regtest), 500_000, &miner);
    let refund = h2.spend(op2, 500_000, Path::Refund, &payout, 2, &user).unwrap();
    let early = node.send(&refund).unwrap_err();
    assert!(early.contains("non-final"), "{early}");
    let now = node.height();
    node.mine((h2.timeout - now) as u64, &miner);
    node.send(&refund).unwrap();
    node.mine(1, &miner);
    // and the claim key cannot refund, nor the refund key claim
    assert!(h2.spend(op2, 500_000, Path::Refund, &payout, 2, &maker).is_err());
}
