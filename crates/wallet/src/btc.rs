//! The Bitcoin side of RQT<->BTC atomic swaps (SWAPS.md §1): a hash/time-locked P2WSH output with the
//! same secret as a Requant HTLC, and the two transfers that spend it.
//!
//! ```text
//! OP_IF    OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <claim key>
//! OP_ELSE  <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund key>
//! OP_ENDIF OP_CHECKSIG
//! ```
//!
//! The secret must be exactly 32 bytes, as on Requant: otherwise a secret of another length could open
//! one side of a swap and not the other. `timeout` is an absolute Bitcoin block height.

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::{
    OP_CHECKSIG, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256, OP_SIZE,
};
use bitcoin::ecdsa::Signature;
use bitcoin::hashes::Hash as _;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Htlc {
    /// SHA-256 of the 32-byte secret.
    pub hash: [u8; 32],
    /// Spends with the secret.
    pub claim: PublicKey,
    /// Spends from `timeout`.
    pub refund: PublicKey,
    /// Absolute block height from which the refund is valid.
    pub timeout: u32,
}

/// How an HTLC output is spent.
#[derive(Clone, Copy, Debug)]
pub enum Path {
    Claim { preimage: [u8; 32] },
    Refund,
}

/// The Bitcoin network of a name: `bitcoin`, `testnet`, `testnet4`, `signet`, `regtest`.
pub fn network(name: &str) -> Result<Network, String> {
    match name {
        "bitcoin" | "main" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("{name}: not a Bitcoin network (bitcoin, testnet, testnet4, signet, regtest)")),
    }
}

/// The compressed public key of a secret key.
pub fn public_key(secret: &[u8; 32]) -> Result<PublicKey, String> {
    let sk = SecretKey::from_slice(secret).map_err(|e| e.to_string())?;
    Ok(PublicKey::new(sk.public_key(&Secp256k1::signing_only())))
}

impl Htlc {
    pub fn script(&self) -> ScriptBuf {
        let hash = PushBytesBuf::try_from(self.hash.to_vec()).expect("32 bytes");
        Builder::new()
            .push_opcode(OP_IF)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(hash)
            .push_opcode(OP_EQUALVERIFY)
            .push_key(&self.claim)
            .push_opcode(OP_ELSE)
            .push_int(self.timeout as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_key(&self.refund)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// The P2WSH address that locks coins under this HTLC.
    pub fn address(&self, net: Network) -> Address {
        Address::p2wsh(&self.script(), net)
    }

    /// A signed transfer of the HTLC output `prev` (worth `value` satoshis) along `path` to `to`, paying
    /// `rate` satoshis per virtual byte. `key` is the claim key or the refund key.
    pub fn spend(
        &self,
        prev: OutPoint,
        value: u64,
        path: Path,
        to: &Address,
        rate: u64,
        key: &[u8; 32],
    ) -> Result<Transaction, String> {
        let sk = SecretKey::from_slice(key).map_err(|e| e.to_string())?;
        let secp = Secp256k1::signing_only();
        let mine = PublicKey::new(sk.public_key(&secp));
        let (lock_time, sequence) = match path {
            Path::Claim { preimage } => {
                if mine != self.claim {
                    return Err("this key is not the claim key of the HTLC".into());
                }
                if bitcoin::hashes::sha256::Hash::hash(&preimage).to_byte_array() != self.hash {
                    return Err("the secret does not hash to the HTLC's hash".into());
                }
                (LockTime::ZERO, Sequence::ENABLE_RBF_NO_LOCKTIME)
            }
            Path::Refund => {
                if mine != self.refund {
                    return Err("this key is not the refund key of the HTLC".into());
                }
                let t = LockTime::from_height(self.timeout).map_err(|e| e.to_string())?;
                // a final sequence would switch the lock time off
                (t, Sequence::ENABLE_LOCKTIME_NO_RBF)
            }
        };
        let script = self.script();
        let build = |fee: u64| -> Result<Transaction, String> {
            let out = value.checked_sub(fee).filter(|v| *v >= 330).ok_or("the HTLC does not cover the fee")?;
            let mut tx = Transaction {
                version: Version::TWO,
                lock_time,
                input: vec![TxIn {
                    previous_output: prev,
                    script_sig: ScriptBuf::new(),
                    sequence,
                    witness: Witness::new(),
                }],
                output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: to.script_pubkey() }],
            };
            let sighash = SighashCache::new(&tx)
                .p2wsh_signature_hash(0, &script, Amount::from_sat(value), EcdsaSighashType::All)
                .map_err(|e| e.to_string())?;
            let sig = Signature {
                signature: secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sk),
                sighash_type: EcdsaSighashType::All,
            };
            let mut w = Witness::new();
            w.push(sig.to_vec());
            match path {
                Path::Claim { preimage } => {
                    w.push(preimage);
                    w.push([1u8]);
                }
                Path::Refund => w.push([]),
            }
            w.push(script.as_bytes());
            tx.input[0].witness = w;
            Ok(tx)
        };
        // the fee follows the size, which the signature fixes within a byte
        let first = build(rate * 200)?;
        build(rate * first.vsize() as u64)
    }
}

/// The secret an HTLC claim revealed: the 32-byte witness item before the `1` that selects the claim path.
pub fn revealed_secret(tx: &Transaction, htlc: &Htlc) -> Option<[u8; 32]> {
    let script = htlc.script();
    tx.input.iter().find_map(|i| {
        let w: Vec<&[u8]> = i.witness.iter().collect();
        if w.len() == 4 && w[3] == script.as_bytes() && w[2] == [1u8] {
            let s: [u8; 32] = w[1].try_into().ok()?;
            (bitcoin::hashes::sha256::Hash::hash(&s).to_byte_array() == htlc.hash).then_some(s)
        } else {
            None
        }
    })
}

/// A minimal JSON-RPC client of a Bitcoin Core node (`user:password` basic auth), for the maker.
pub struct Bitcoind {
    addr: std::net::SocketAddr,
    auth: String,
}

pub(crate) fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            out.push(if k <= c.len() { T[(n >> (18 - 6 * k) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

impl Bitcoind {
    /// `addr`: host:port of the node's RPC; `user_pass`: `user:password` (as in rpcauth or a .cookie file).
    pub fn new(addr: &str, user_pass: &str) -> Result<Bitcoind, String> {
        use std::net::ToSocketAddrs;
        let addr = addr.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("no address")?;
        Ok(Bitcoind { addr, auth: base64(user_pass.trim().as_bytes()) })
    }

    pub fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        use std::io::{Read, Write};
        let body = serde_json::json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut s = std::net::TcpStream::connect_timeout(&self.addr, std::time::Duration::from_secs(15))
            .map_err(|e| format!("bitcoind: {e}"))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(120))).map_err(|e| e.to_string())?;
        write!(
            s,
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.auth,
            body.len()
        )
        .map_err(|e| e.to_string())?;
        let mut resp = String::new();
        s.read_to_string(&mut resp).map_err(|e| format!("bitcoind: {e}"))?;
        let json = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let v: serde_json::Value = serde_json::from_str(json)
            .map_err(|_| "bitcoind: not a JSON answer (check the RPC credentials)".to_string())?;
        if !v["error"].is_null() {
            return Err(format!("bitcoind: {}", v["error"]["message"].as_str().unwrap_or("error")));
        }
        Ok(v["result"].clone())
    }

    pub fn height(&self) -> Result<u32, String> {
        self.call("getblockcount", serde_json::json!([]))?.as_u64().map(|h| h as u32).ok_or("bad getblockcount".into())
    }

    /// Confirmed outputs paying `address`: `(outpoint, satoshis, height)`.
    pub fn unspent(&self, address: &Address) -> Result<Vec<(OutPoint, u64, u32)>, String> {
        let r = self.call("scantxoutset", serde_json::json!(["start", [format!("addr({address})")]]))?;
        let list = r["unspents"].as_array().ok_or("bad scantxoutset")?;
        list.iter()
            .map(|u| {
                let txid = u["txid"].as_str().and_then(|t| t.parse().ok()).ok_or("bad txid")?;
                let vout = u["vout"].as_u64().ok_or("bad vout")? as u32;
                let sats = (u["amount"].as_f64().ok_or("bad amount")? * 1e8).round() as u64;
                Ok((OutPoint { txid, vout }, sats, u["height"].as_u64().unwrap_or(0) as u32))
            })
            .collect()
    }

    pub fn send(&self, tx: &Transaction) -> Result<String, String> {
        let txid =
            self.call("sendrawtransaction", serde_json::json!([bitcoin::consensus::encode::serialize_hex(tx)]))?;
        Ok(txid.as_str().unwrap_or_default().to_string())
    }

    /// Confirmations of a transaction this node knows (0 while pooled; None when unknown). A pruned node
    /// without -txindex finds a confirmed one through its first output while that is unspent.
    pub fn confirmations(&self, txid: &str) -> Option<u64> {
        if let Ok(v) = self.call("getrawtransaction", serde_json::json!([txid, true])) {
            return Some(v["confirmations"].as_u64().unwrap_or(0));
        }
        let out = self.call("gettxout", serde_json::json!([txid, 0, true])).ok()?;
        out["confirmations"].as_u64()
    }

    /// Whether the node is still catching up with the chain.
    pub fn syncing(&self) -> Result<bool, String> {
        Ok(self.call("getblockchaininfo", serde_json::json!([]))?["initialblockdownload"].as_bool().unwrap_or(true))
    }

    /// A fee rate in satoshis per virtual byte for confirmation within `blocks` (2 when the node has no estimate).
    pub fn fee_rate(&self, blocks: u32) -> u64 {
        self.call("estimatesmartfee", serde_json::json!([blocks]))
            .ok()
            .and_then(|v| v["feerate"].as_f64())
            .map(|btc_per_kvb| ((btc_per_kvb * 1e8 / 1000.0).ceil() as u64).max(1))
            .unwrap_or(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};

    fn htlc() -> Htlc {
        Htlc {
            hash: bitcoin::hashes::sha256::Hash::hash(&[7u8; 32]).to_byte_array(),
            claim: public_key(&[1; 32]).unwrap(),
            refund: public_key(&[2; 32]).unwrap(),
            timeout: 300,
        }
    }

    #[test]
    fn script_address_and_both_paths() {
        let h = htlc();
        let s = h.script();
        // OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <32> OP_EQUALVERIFY <33> OP_ELSE <300> OP_CLTV OP_DROP <33> OP_ENDIF OP_CHECKSIG
        assert_eq!(s.len(), 1 + 1 + 2 + 1 + 1 + 33 + 1 + 34 + 1 + 3 + 1 + 1 + 34 + 1 + 1);
        let addr = h.address(Network::Regtest);
        assert!(addr.to_string().starts_with("bcrt1q"));
        assert_eq!(addr.script_pubkey(), ScriptBuf::new_p2wsh(&s.wscript_hash()));
        let prev = OutPoint { txid: bitcoin::Txid::all_zeros(), vout: 1 };
        let to = h.address(Network::Regtest);
        let claim = h.spend(prev, 100_000, Path::Claim { preimage: [7; 32] }, &to, 2, &[1; 32]).unwrap();
        assert_eq!(claim.lock_time, LockTime::ZERO);
        assert_eq!(revealed_secret(&claim, &h), Some([7; 32]));
        let fee = 100_000 - claim.output[0].value.to_sat();
        assert_eq!(fee, 2 * claim.vsize() as u64);
        let back: Transaction = deserialize_hex(&serialize_hex(&claim)).unwrap();
        assert_eq!(back, claim);
        let refund = h.spend(prev, 100_000, Path::Refund, &to, 2, &[2; 32]).unwrap();
        assert_eq!(refund.lock_time, LockTime::from_height(300).unwrap());
        assert_eq!(refund.input[0].sequence, Sequence::ENABLE_LOCKTIME_NO_RBF);
        assert_eq!(revealed_secret(&refund, &h), None);
    }

    #[test]
    fn basic_auth_encoding() {
        assert_eq!(base64(b"u:p"), "dTpw");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"ab"), "YWI=");
    }

    #[test]
    fn wrong_keys_secrets_and_amounts_are_refused() {
        let h = htlc();
        let prev = OutPoint { txid: bitcoin::Txid::all_zeros(), vout: 0 };
        let to = h.address(Network::Regtest);
        assert!(h.spend(prev, 100_000, Path::Claim { preimage: [8; 32] }, &to, 1, &[1; 32]).is_err());
        assert!(h.spend(prev, 100_000, Path::Claim { preimage: [7; 32] }, &to, 1, &[2; 32]).is_err());
        assert!(h.spend(prev, 100_000, Path::Refund, &to, 1, &[1; 32]).is_err());
        assert!(h.spend(prev, 500, Path::Refund, &to, 1, &[2; 32]).is_err());
        assert!(network("dogecoin").is_err());
    }
}
