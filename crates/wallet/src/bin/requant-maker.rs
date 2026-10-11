//! `requant-maker`: sells RQT for BTC over atomic swaps (SWAPS.md §1; protocol in `swap.rs`).
//!
//! requant-maker btc-keygen FILE          a Bitcoin key for the maker's claims (hex, kept private)
//! requant-maker run CONFIG.json          serve takers and run the swaps
//!
//! CONFIG.json:
//! {"rqt_network": "test", "rqt_api": "http://127.0.0.1:19380", "rqt_key": "maker.key",
//!  "btc_network": "signet", "bitcoind": "127.0.0.1:38332", "bitcoind_auth": "bitcoind.auth",
//!  "btc_key": "maker-btc.key", "btc_payout": "tb1q...", "sats_per_rqt": 1000,
//!  "min_rqt": 10000000, "max_rqt": 10000000000, "listen": "127.0.0.1:19390", "state": "maker-state.json",
//!  "tick_seconds": 10}
//!
//! `rqt_key` is a requant-wallet key file (REQUANT_WALLET_PASSPHRASE when it is encrypted); it pays the
//! RQT locks and receives refunds. `bitcoind_auth` holds `user:password` or is the node's `.cookie`.
//! Takers call JSON-RPC `info`, `swap_create [rqt_atoms, hash, btc_refund_pubkey, rqt_address]` and
//! `swap_status [id]`.

use requant_consensus::params::Network;
use requant_node::rpc::{hex, serve_with, Handler};
use requant_wallet::btc::{self, Bitcoind};
use requant_wallet::maker::{Config, Maker};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn die(msg: &str) -> ! {
    eprintln!("requant-maker: {msg}");
    std::process::exit(1)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}")))
}

fn key32(path: &str) -> [u8; 32] {
    requant_node::rpc::unhex(read(path).trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| die(&format!("{path}: expected 64 hex digits")))
}

fn config(path: &str) -> (Config, String, u64) {
    let c: Value = serde_json::from_str(&read(path)).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let s = |k: &str| c[k].as_str().map(str::to_string).unwrap_or_else(|| die(&format!("{path}: {k} missing")));
    let n = |k: &str| c[k].as_u64().unwrap_or_else(|| die(&format!("{path}: {k} must be a number")));
    let rqt_network = Network::by_name(&s("rqt_network")).unwrap_or_else(|| die("rqt_network: test or regtest"));
    let btc_network = btc::network(&s("btc_network")).unwrap_or_else(|e| die(&e));
    let rqt_key_text = read(&s("rqt_key"));
    let pass = std::env::var("REQUANT_WALLET_PASSPHRASE").ok();
    let rqt_key =
        requant_wallet::decrypt_key(&rqt_key_text, pass.as_deref()).unwrap_or_else(|e| die(&format!("rqt_key: {e}")));
    let bitcoind = Bitcoind::new(&s("bitcoind"), read(&s("bitcoind_auth")).trim()).unwrap_or_else(|e| die(&e));
    let btc_payout = s("btc_payout")
        .parse::<bitcoin::Address<_>>()
        .ok()
        .and_then(|a| a.require_network(btc_network).ok())
        .unwrap_or_else(|| die("btc_payout: an address of btc_network"));
    let cfg = Config {
        rqt_network,
        rqt_api: s("rqt_api"),
        rqt_key,
        btc_network,
        bitcoind,
        btc_key: key32(&s("btc_key")),
        btc_payout,
        sats_per_rqt: n("sats_per_rqt"),
        min_rqt: n("min_rqt"),
        max_rqt: n("max_rqt"),
        state: s("state").into(),
    };
    (cfg, s("listen"), c["tick_seconds"].as_u64().unwrap_or(10))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["btc-keygen", file] => {
            if std::path::Path::new(file).exists() {
                die(&format!("{file} exists; refusing to overwrite it"));
            }
            let mut secret = [0u8; 32];
            getrandom::getrandom(&mut secret).unwrap_or_else(|e| die(&e.to_string()));
            let pubkey = btc::public_key(&secret).unwrap_or_else(|e| die(&e));
            std::fs::write(file, hex(&secret)).unwrap_or_else(|e| die(&e.to_string()));
            println!("Bitcoin key written to {file} (keep it private)\npubkey {pubkey}");
        }
        ["run", path] => {
            let (cfg, listen, tick) = config(path);
            let maker = Arc::new(Mutex::new(Maker::new(cfg).unwrap_or_else(|e| die(&e))));
            let m = maker.clone();
            let handler: Handler = Arc::new(move |method: &str, p: &[Value]| {
                let arg = |k: usize| p.get(k).ok_or_else(|| format!("missing parameter {k}"));
                let mut mk = m.lock().unwrap_or_else(|e| e.into_inner());
                match method {
                    "info" => Ok(mk.info()),
                    "swap_create" => {
                        let atoms = arg(0)?.as_u64().ok_or("parameter 0: atoms")?;
                        let text = |k: usize| {
                            arg(k).and_then(|v| v.as_str().map(str::to_string).ok_or(format!("parameter {k}: text")))
                        };
                        mk.create(atoms, &text(1)?, &text(2)?, &text(3)?)
                    }
                    "swap_status" => mk.status(arg(0)?.as_str().ok_or("parameter 0: id")?),
                    _ => Err(format!("unknown method {method}")),
                }
            });
            let at =
                serve_with(listen.parse().unwrap_or_else(|_| die("listen: host:port")), vec![], 1 << 16, 64, handler)
                    .unwrap_or_else(|e| die(&format!("listen: {e}")));
            eprintln!("requant-maker on {at}: {}", json!(maker.lock().unwrap().info()));
            loop {
                for line in maker.lock().unwrap_or_else(|e| e.into_inner()).tick() {
                    eprintln!("{line}");
                }
                std::thread::sleep(std::time::Duration::from_secs(tick));
            }
        }
        _ => die("usage: requant-maker btc-keygen FILE | run CONFIG.json"),
    }
}
