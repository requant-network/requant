//! The maker of RQT<->BTC swaps (`requant-maker`; protocol in `swap.rs`): it sells RQT for BTC at a set
//! price. Each swap goes through
//!
//! `waiting_btc` → `rqt_locked` → `btc_claimed`, or ends `expired` (never paid in time), `too_late` (paid
//! with too little Bitcoin time left: the taker takes the BTC back), `underpaid`, or `rqt_refunded` (the
//! taker never claimed the RQT).
//!
//! A tick, every few seconds, moves each swap on from what the two chains show. State is one JSON file,
//! written to a temporary file and renamed, so a crash never loses a swap.

use crate::backend::Backend;
use crate::btc::{self, Bitcoind};
use crate::contracts::{self, Condition};
use crate::swap::{self, BTC_TIMEOUT_BLOCKS, MIN_BTC_BLOCKS_LEFT, RQT_TIMEOUT_BLOCKS};
use crate::{owner_of, plan_payment, sign_with, Spendable};
use ed25519_dalek::SigningKey;
use requant_consensus::params::Network;
use requant_consensus::tx::{Hash, Htlc as RqtHtlc, OutPoint as RqtOutPoint, Tx};
use requant_node::rpc::{hex, unhex};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Bitcoin blocks (about two hours) the taker has to pay a new swap; later payments are not answered.
pub const FUNDING_WINDOW: u32 = 12;
/// The Requant fee rate of the maker's locks and refunds (atoms per byte).
const RQT_FEE_RATE: u64 = 2;

pub struct Config {
    pub rqt_network: Network,
    pub rqt_api: String,
    pub rqt_key: [u8; 32],
    pub btc_network: bitcoin::Network,
    pub bitcoind: Bitcoind,
    pub btc_key: [u8; 32],
    pub btc_payout: bitcoin::Address,
    pub sats_per_rqt: u64,
    pub min_rqt: u64,
    pub max_rqt: u64,
    pub state: std::path::PathBuf,
}

pub struct Maker {
    pub cfg: Config,
    rqt: Backend,
    key: SigningKey,
    swaps: Vec<Value>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Maker {
    pub fn new(cfg: Config) -> Result<Maker, String> {
        let rqt = Backend::api(&cfg.rqt_api)?;
        let swaps = match std::fs::read_to_string(&cfg.state) {
            Ok(t) => serde_json::from_str::<Value>(&t).map_err(|e| format!("state: {e}"))?["swaps"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let key = SigningKey::from_bytes(&cfg.rqt_key);
        Ok(Maker { cfg, rqt, key, swaps })
    }

    fn save(&self) -> Result<(), String> {
        let tmp = self.cfg.state.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&json!({"swaps": self.swaps})).unwrap())
            .and_then(|_| std::fs::rename(&tmp, &self.cfg.state))
            .map_err(|e| format!("state: {e}"))
    }

    fn me(&self) -> Hash {
        owner_of(&self.key)
    }

    fn btc_pubkey(&self) -> bitcoin::PublicKey {
        btc::public_key(&self.cfg.btc_key).expect("the maker's Bitcoin key")
    }

    fn rqt_height(&self) -> Result<u64, String> {
        let v = self.rqt.call("getinfo", json!([])).map_err(|e| e.to_string())?;
        v["height"].as_u64().ok_or("requant: no height".into())
    }

    /// What takers are told: networks, price, limits, keys and time locks.
    pub fn info(&self) -> Value {
        json!({"rqt_network": self.cfg.rqt_network.name, "btc_network": self.cfg.btc_network.to_string(),
               "sats_per_rqt": self.cfg.sats_per_rqt, "min_rqt": self.cfg.min_rqt, "max_rqt": self.cfg.max_rqt,
               "btc_pubkey": self.btc_pubkey().to_string(), "rqt_refund": hex(&self.me()),
               "btc_timeout_blocks": BTC_TIMEOUT_BLOCKS, "rqt_timeout_blocks": RQT_TIMEOUT_BLOCKS,
               "funding_window_blocks": FUNDING_WINDOW})
    }

    /// A new swap: the taker's amount, secret hash, Bitcoin refund key and Requant address (key hash).
    pub fn create(&mut self, rqt_atoms: u64, hash: &str, refund: &str, claim: &str) -> Result<Value, String> {
        if rqt_atoms < self.cfg.min_rqt || rqt_atoms > self.cfg.max_rqt {
            return Err(format!("amount: from {} to {} atoms", self.cfg.min_rqt, self.cfg.max_rqt));
        }
        let hash: [u8; 32] = unhex(hash).ok().and_then(|b| b.try_into().ok()).ok_or("hash: 64 hex digits")?;
        let refund: bitcoin::PublicKey = refund.parse().map_err(|_| "refund: a compressed public key")?;
        if !refund.compressed {
            return Err("refund: a compressed public key".into());
        }
        let claim = contracts::who(&self.cfg.rqt_network, claim)?;
        let id = hex(&hash);
        if self.swaps.iter().any(|s| s["id"] == json!(id)) {
            return Err("a swap with this hash exists: use a new secret".into());
        }
        let btc_tip = self.cfg.bitcoind.height()?;
        let h = btc::Htlc { hash, claim: self.btc_pubkey(), refund, timeout: btc_tip + BTC_TIMEOUT_BLOCKS };
        let sats = swap::price(rqt_atoms, self.cfg.sats_per_rqt);
        let s = json!({"id": id, "state": "waiting_btc", "created": now(), "created_btc_height": btc_tip,
                       "rqt_atoms": rqt_atoms, "btc_sats": sats, "taker_claim": hex(&claim),
                       "btc_htlc": swap::btc_htlc_json(&h, self.cfg.btc_network),
                       "confirmations": swap::btc_confirmations(sats)});
        self.swaps.push(s.clone());
        self.save()?;
        Ok(s)
    }

    pub fn status(&self, id: &str) -> Result<Value, String> {
        self.swaps.iter().find(|s| s["id"] == json!(id)).cloned().ok_or("no such swap".into())
    }

    /// Move every open swap on; returns what happened, for the log.
    pub fn tick(&mut self) -> Vec<String> {
        let mut log = Vec::new();
        let (btc_tip, rqt_tip) = match (self.cfg.bitcoind.height(), self.rqt_height()) {
            (Ok(b), Ok(r)) => (b, r),
            (b, r) => {
                log.push(format!("chains unreachable: {:?} {:?}", b.err(), r.err()));
                return log;
            }
        };
        for k in 0..self.swaps.len() {
            let state = self.swaps[k]["state"].as_str().unwrap_or("").to_string();
            let step = match state.as_str() {
                "waiting_btc" => self.step_funding(k, btc_tip, rqt_tip),
                "rqt_locked" => self.step_locked(k, rqt_tip),
                "btc_claimed" => self.step_claimed(k),
                _ => Ok(None),
            };
            match step {
                Ok(Some(what)) => {
                    log.push(format!("{}: {what}", &self.swaps[k]["id"].as_str().unwrap_or("")[..12]));
                    let _ = self.save();
                }
                Ok(None) => {}
                Err(e) => log.push(format!("{}: {e}", &self.swaps[k]["id"].as_str().unwrap_or("")[..12])),
            }
        }
        log
    }

    fn set(&mut self, k: usize, fields: Value) {
        for (key, v) in fields.as_object().unwrap() {
            self.swaps[k][key] = v.clone();
        }
    }

    /// Wait for the taker's Bitcoin payment; lock the RQT once it has its confirmations.
    fn step_funding(&mut self, k: usize, btc_tip: u32, rqt_tip: u64) -> Result<Option<String>, String> {
        let s = self.swaps[k].clone();
        let h = swap::btc_htlc_from(&s["btc_htlc"])?;
        let paid = self.cfg.bitcoind.unspent(&h.address(self.cfg.btc_network))?;
        let Some((op, sats, height)) = paid.into_iter().max_by_key(|p| p.1) else {
            if btc_tip > s["created_btc_height"].as_u64().unwrap_or(0) as u32 + FUNDING_WINDOW {
                self.set(k, json!({"state": "expired"}));
                return Ok(Some("expired unpaid".into()));
            }
            return Ok(None);
        };
        let need = s["btc_sats"].as_u64().unwrap_or(u64::MAX);
        if sats < need {
            self.set(
                k,
                json!({"state": "underpaid", "funding": {"txid": op.txid.to_string(), "vout": op.vout, "sats": sats}}),
            );
            return Ok(Some(format!(
                "underpaid: {sats} of {need} satoshis; the taker takes them back after the timeout"
            )));
        }
        let confirmations = btc_tip.saturating_sub(height) + 1;
        if confirmations < s["confirmations"].as_u64().unwrap_or(6) as u32 {
            return Ok(None);
        }
        let funding = json!({"txid": op.txid.to_string(), "vout": op.vout, "sats": sats, "height": height});
        if h.timeout.saturating_sub(btc_tip) < MIN_BTC_BLOCKS_LEFT
            || height > s["created_btc_height"].as_u64().unwrap_or(0) as u32 + FUNDING_WINDOW
        {
            self.set(k, json!({"state": "too_late", "funding": funding}));
            return Ok(Some("paid too late: not locking RQT; the taker takes the BTC back after the timeout".into()));
        }
        // lock the RQT under the same hash, refund to the maker
        let claim: Hash =
            unhex(s["taker_claim"].as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok()).ok_or("bad claim")?;
        let lock = RqtHtlc { hash: h.hash, claim, refund: self.me(), timeout: rqt_tip + RQT_TIMEOUT_BLOCKS };
        let owner = Condition::Htlc(lock).owner();
        let txid = self.pay(owner, s["rqt_atoms"].as_u64().unwrap_or(0))?;
        self.set(
            k,
            json!({"state": "rqt_locked", "funding": funding, "rqt_htlc": swap::rqt_htlc_json(&lock),
                           "rqt_lock_txid": txid}),
        );
        Ok(Some(format!("BTC confirmed ({confirmations}); RQT locked in {txid}")))
    }

    /// Pay `atoms` to `owner` from the maker's key (change back to it); the txid.
    fn pay(&self, owner: Hash, atoms: u64) -> Result<String, String> {
        let me = self.me();
        let coins = self.rqt.call("utxos", json!([hex(&me)])).map_err(|e| e.to_string())?;
        let spendable: Vec<Spendable> = coins
            .as_array()
            .ok_or("requant: bad utxos")?
            .iter()
            .filter(|c| c["spendable"].as_bool() == Some(true))
            .filter_map(|c| {
                let txid: Hash = unhex(c["txid"].as_str()?).ok()?.try_into().ok()?;
                Some(Spendable {
                    op: RqtOutPoint { txid, vout: c["vout"].as_u64()? as u32 },
                    value: c["value"].as_u64()?,
                    owner: me,
                })
            })
            .collect();
        let (mut tx, chosen, _) = plan_payment(&spendable, &[(owner, atoms)], RQT_FEE_RATE, me)?;
        sign_with(&self.cfg.rqt_network, &mut tx, &chosen, &HashMap::from([(me, self.key.clone())]))?;
        self.send_rqt(&tx)
    }

    fn send_rqt(&self, tx: &Tx) -> Result<String, String> {
        let txid = self.rqt.call("sendtx", json!([hex(&tx.encode())])).map_err(|e| format!("requant: {e}"))?;
        Ok(txid.as_str().unwrap_or_default().to_string())
    }

    /// The RQT are locked: when the taker claims them, read the secret and claim the BTC; refund the RQT
    /// when the taker never does.
    fn step_locked(&mut self, k: usize, rqt_tip: u64) -> Result<Option<String>, String> {
        let s = self.swaps[k].clone();
        let lock = swap::rqt_htlc_from(&s["rqt_htlc"])?;
        let owner = Condition::Htlc(lock).owner();
        let coins = self.rqt.call("utxos", json!([hex(&owner)])).map_err(|e| e.to_string())?;
        let coins: Vec<(RqtOutPoint, u64)> = coins
            .as_array()
            .ok_or("requant: bad utxos")?
            .iter()
            .filter_map(|c| {
                let txid: Hash = unhex(c["txid"].as_str()?).ok()?.try_into().ok()?;
                Some((RqtOutPoint { txid, vout: c["vout"].as_u64()? as u32 }, c["value"].as_u64()?))
            })
            .collect();
        if let Some(secret) = self.secret_on_requant(&owner, &lock, &s)? {
            let h = swap::btc_htlc_from(&s["btc_htlc"])?;
            let f = &s["funding"];
            let op = bitcoin::OutPoint {
                txid: f["txid"].as_str().unwrap_or("").parse().map_err(|_| "bad funding txid")?,
                vout: f["vout"].as_u64().unwrap_or(0) as u32,
            };
            let rate = self.cfg.bitcoind.fee_rate(6);
            let tx = h.spend(
                op,
                f["sats"].as_u64().unwrap_or(0),
                btc::Path::Claim { preimage: secret },
                &self.cfg.btc_payout,
                rate,
                &self.cfg.btc_key,
            )?;
            let txid = self.cfg.bitcoind.send(&tx)?;
            self.set(
                k,
                json!({"state": "btc_claimed", "secret": hex(&secret), "btc_claim_txid": txid,
                               "btc_claim_hex": bitcoin::consensus::encode::serialize_hex(&tx)}),
            );
            return Ok(Some(format!("secret revealed on Requant; BTC claimed in {txid}")));
        }
        if !coins.is_empty() && rqt_tip + 1 >= lock.timeout {
            let (mut tx, _) =
                contracts::spend(&Condition::Htlc(lock), "refund", &coins, &self.me(), RQT_FEE_RATE, None, false)?;
            tx.sign(&self.cfg.rqt_network.chain_id, &vec![&self.key; coins.len()]);
            let txid = self.send_rqt(&tx)?;
            self.set(k, json!({"state": "rqt_refunded", "rqt_refund_txid": txid}));
            return Ok(Some(format!("the taker never claimed; RQT refunded in {txid}")));
        }
        Ok(None)
    }

    /// The secret, if a transfer spending the lock revealed it.
    fn secret_on_requant(&self, owner: &Hash, lock: &RqtHtlc, s: &Value) -> Result<Option<[u8; 32]>, String> {
        let history = self.rqt.call("history", json!([hex(owner), 20])).map_err(|e| e.to_string())?;
        for e in history.as_array().into_iter().flatten() {
            if e["sent"].as_u64().unwrap_or(0) == 0 {
                continue;
            }
            let txid = e["txid"].as_str().unwrap_or("");
            if Some(txid) == s["rqt_refund_txid"].as_str() {
                continue;
            }
            let v = self.rqt.call("gettx", json!([txid])).map_err(|e| e.to_string())?;
            let raw = v["hex"].as_str().and_then(|h| unhex(h).ok()).ok_or("requant: gettx gave no hex")?;
            let tx = Tx::decode_exact(&raw).map_err(|e| e.to_string())?;
            if let Some(secret) = swap::revealed_on_requant(&tx, lock) {
                return Ok(Some(secret));
            }
        }
        Ok(None)
    }

    /// The BTC claim is out: rebroadcast it until it confirms.
    fn step_claimed(&mut self, k: usize) -> Result<Option<String>, String> {
        let s = &self.swaps[k];
        let txid = s["btc_claim_txid"].as_str().unwrap_or("").to_string();
        match self.cfg.bitcoind.confirmations(&txid) {
            Some(c) if c > 0 => {
                self.set(k, json!({"state": "done"}));
                Ok(Some(format!("BTC claim confirmed ({c})")))
            }
            _ => {
                let raw = s["btc_claim_hex"].as_str().unwrap_or("").to_string();
                let _ = self.cfg.bitcoind.call("sendrawtransaction", json!([raw]));
                Ok(None)
            }
        }
    }
}
