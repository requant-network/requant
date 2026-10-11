//! `requant-maker`: sells RQT for BTC over atomic swaps (SWAPS.md §1; protocol in `swap.rs`).
//!
//! requant-maker btc-keygen FILE          a Bitcoin key for the maker's claims (hex, kept private)
//! requant-maker btc-address FILE NETWORK the P2WPKH address of that key (a place for the BTC it claims)
//! requant-maker tron-keygen FILE         a TRON key: it receives the USDT the maker claims
//! requant-maker tron-address FILE        that key's TRON address (fund it with TRX for claim fees)
//! requant-maker tron-status FILE NETWORK its TRX, USDT, energy and stake
//! requant-maker tron-stake FILE NETWORK TRX   stake TRX for energy: the maker's claims use it, and it
//!                                        lends it to takers for their locks (else it sends TRX to burn)
//! requant-maker run CONFIG.json          serve takers and run the swaps
//!
//! CONFIG.json:
//! {"rqt_network": "test", "rqt_api": "http://127.0.0.1:19380", "rqt_key": "maker.key",
//!  "btc_network": "signet", "bitcoind": "127.0.0.1:38332", "bitcoind_auth": "bitcoind.auth",
//!  "btc_key": "maker-btc.key", "btc_payout": "tb1q...", "sats_per_rqt": 1000,
//!  "min_rqt": 10000000, "max_rqt": 10000000000, "listen": "127.0.0.1:19390", "state": "maker-state.json",
//!  "tick_seconds": 10}
//!
//! Optional Lightning: "lnd": {"rest": "127.0.0.1:8080", "macaroon": "invoices.macaroon"} (LND with
//! --no-rest-tls on the same host; a macaroon that may add, settle and cancel invoices).
//!
//! Optional USDT on TRON: "tron": {"network": "nile", "key": "maker.tron", "units_per_rqt": 100000,
//! "api": "https://nile.trongrid.io"} (units: millionths of a USDT; api defaults to the network's).
//!
//! `rqt_key` is a requant-wallet key file (REQUANT_WALLET_PASSPHRASE when it is encrypted); it pays the
//! RQT locks and receives refunds. `bitcoind_auth` holds `user:password` or is the node's `.cookie`.
//! Takers call JSON-RPC `info`, `swap_create [rqt_atoms, hash, btc_refund_pubkey, rqt_address]` and
//! `swap_status [id]`; `swap_create_ln [rqt_atoms, hash, rqt_address]` and
//! `swap_create_usdt [rqt_atoms, hash, tron_sender, rqt_address]` and `swap_fees [id]` (the maker pays the
//! fees of the taker's lock) when configured.

use requant_consensus::params::Network;
use requant_node::rpc::{hex, serve_with, Handler};
use requant_wallet::btc::{self, Bitcoind};
use requant_wallet::maker::{Config, Maker, TronSide};
use requant_wallet::tron::{self, Tron};
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
        lnd: c["lnd"].as_object().map(|l| {
            let rest = l.get("rest").and_then(|v| v.as_str()).unwrap_or_else(|| die("lnd.rest missing"));
            let mac = l.get("macaroon").and_then(|v| v.as_str()).unwrap_or_else(|| die("lnd.macaroon missing"));
            let bytes = std::fs::read(mac).unwrap_or_else(|e| die(&format!("{mac}: {e}")));
            requant_wallet::ln::Lnd::new(rest, &bytes).unwrap_or_else(|e| die(&e))
        }),
        tron: c["tron"].as_object().map(|t| {
            let text = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or_else(|| die(&format!("tron.{k} missing")));
            let network = text("network").to_string();
            let d = tron::deployment(&network).unwrap_or_else(|e| die(&e));
            TronSide {
                api: Tron::new(t.get("api").and_then(|v| v.as_str()).unwrap_or(d.api)),
                key: key32(text("key")),
                units_per_rqt: t
                    .get("units_per_rqt")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| die("tron.units_per_rqt")),
                network,
            }
        }),
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
        ["tron-keygen", file] => {
            if std::path::Path::new(file).exists() {
                die(&format!("{file} exists; refusing to overwrite it"));
            }
            let mut secret = [0u8; 32];
            getrandom::getrandom(&mut secret).unwrap_or_else(|e| die(&e.to_string()));
            let a = tron::address_of(&secret).unwrap_or_else(|e| die(&e));
            std::fs::write(file, hex(&secret)).unwrap_or_else(|e| die(&e.to_string()));
            println!("TRON key written to {file} (keep it private)
address {}", tron::to_base58(&a));
        }
        ["tron-address", file] => {
            println!("{}", tron::to_base58(&tron::address_of(&key32(file)).unwrap_or_else(|e| die(&e))));
        }
        ["tron-status", file, network] => {
            let api = Tron::new(tron::deployment(network).unwrap_or_else(|e| die(&e)).api);
            let me = tron::address_of(&key32(file)).unwrap_or_else(|e| die(&e));
            let d = tron::deployment(network).unwrap();
            let usdt = api.token_balance(&tron::parse(d.usdt).unwrap(), &me).unwrap_or_else(|e| die(&e));
            println!("address   {}", tron::to_base58(&me));
            println!("TRX       {}", api.trx_balance(&me).unwrap_or_else(|e| die(&e)) as f64 / 1e6);
            println!("USDT      {}", tron::format_units(usdt));
            println!("energy    {} now; lendable stake {} TRX", api.energy(&me).unwrap_or(0), api.can_delegate(&me).unwrap_or(0) as f64 / 1e6);
            let one = tron::APPROVE_ENERGY + tron::LOCK_ENERGY;
            println!("one lock  {one} energy = {} TRX staked", api.stake_for_energy(&me, one).unwrap_or(0) / 1_000_000);
        }
        ["tron-stake", file, network, trx] => {
            let api = Tron::new(tron::deployment(network).unwrap_or_else(|e| die(&e)).api);
            let key = key32(file);
            let me = tron::address_of(&key).unwrap_or_else(|e| die(&e));
            let sun = trx.parse::<u64>().unwrap_or_else(|_| die("TRX: a whole number")) * 1_000_000;
            let raw = tron::freeze_energy(&api.now_block().unwrap_or_else(|e| die(&e)), &me, sun);
            println!("staked for energy in {}", api.send_raw(&key, &raw).unwrap_or_else(|e| die(&e)));
        }
        ["btc-address", file, network] => {
            let net = btc::network(network).unwrap_or_else(|e| die(&e));
            let pubkey = btc::public_key(&key32(file)).unwrap_or_else(|e| die(&e));
            let compressed = bitcoin::CompressedPublicKey::try_from(pubkey).unwrap_or_else(|e| die(&e.to_string()));
            println!("{}", bitcoin::Address::p2wpkh(&compressed, net));
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
                    "swap_create_ln" => {
                        let atoms = arg(0)?.as_u64().ok_or("parameter 0: atoms")?;
                        let text = |k: usize| {
                            arg(k).and_then(|v| v.as_str().map(str::to_string).ok_or(format!("parameter {k}: text")))
                        };
                        mk.create_ln(atoms, &text(1)?, &text(2)?)
                    }
                    "swap_create_usdt" => {
                        let atoms = arg(0)?.as_u64().ok_or("parameter 0: atoms")?;
                        let text = |k: usize| {
                            arg(k).and_then(|v| v.as_str().map(str::to_string).ok_or(format!("parameter {k}: text")))
                        };
                        mk.create_token(atoms, &text(1)?, &text(2)?, &text(3)?)
                    }
                    "swap_fees" => mk.pay_fees(arg(0)?.as_str().ok_or("parameter 0: id")?),
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
        _ => die("usage: requant-maker btc-keygen FILE | btc-address FILE NETWORK | tron-keygen FILE | tron-address FILE | tron-status FILE NETWORK | tron-stake FILE NETWORK TRX | run CONFIG.json"),
    }
}
