//! TRON side of RQT<->TRC-20 swaps (USDT): keys and addresses, calls of the RequantHtlc
//! contract (`contracts/src/RequantHtlc.sol`), and transactions built and signed here. The protobuf of a
//! transaction is written by hand, so the TRON API (TronGrid or a node) is never trusted with what is
//! signed; it only reads chain state and relays signed transactions.

use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use requant_node::rpc::{hex, unhex};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

/// A TRON address: 0x41 and the last 20 bytes of the Keccak-256 of the uncompressed public key.
pub type Addr = [u8; 21];

/// The swap contract and the USDT token of a TRON network, and a public API for it.
pub struct Deployment {
    pub network: &'static str,
    pub htlc: &'static str,
    pub usdt: &'static str,
    pub api: &'static str,
}

/// Contracts the wallet accepts: a maker can only point takers at these, never at a contract of its own.
pub const DEPLOYMENTS: &[Deployment] = &[Deployment {
    network: "nile",
    htlc: "TBBkQ4hqoH9Ji21QQ5mb6t22MxjWknFiwk",
    usdt: "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
    api: "https://nile.trongrid.io",
}];

pub fn deployment(network: &str) -> Result<&'static Deployment, String> {
    DEPLOYMENTS
        .iter()
        .find(|d| d.network == network)
        .ok_or(format!("TRON network {network}: no swap contract known (nile)"))
}

pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

pub fn address_of(secret: &[u8; 32]) -> Result<Addr, String> {
    let sk = SecretKey::from_slice(secret).map_err(|e| format!("TRON key: {e}"))?;
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize_uncompressed();
    let mut a = [0x41; 21];
    a[1..].copy_from_slice(&keccak(&pk[1..])[12..]);
    Ok(a)
}

pub fn to_base58(a: &Addr) -> String {
    bitcoin::base58::encode_check(a)
}

pub fn parse(s: &str) -> Result<Addr, String> {
    let b = bitcoin::base58::decode_check(s).map_err(|_| format!("{s}: not a TRON address"))?;
    match <Addr>::try_from(b) {
        Ok(a @ [0x41, ..]) => Ok(a),
        _ => Err(format!("{s}: not a TRON address")),
    }
}

// ---- ABI ------------------------------------------------------------------------------------------

fn selector(signature: &str) -> Vec<u8> {
    keccak(signature.as_bytes())[..4].to_vec()
}

fn word_addr(out: &mut Vec<u8>, a: &Addr) {
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&a[1..]);
}

fn word_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&[0; 24]);
    out.extend_from_slice(&v.to_be_bytes());
}

/// The low 64 bits of a returned uint256, refusing anything larger.
pub fn decode_u64(word: &[u8]) -> Result<u64, String> {
    if word.len() < 32 || word[..24].iter().any(|b| *b != 0) {
        return Err("a contract returned an out-of-range number".into());
    }
    Ok(u64::from_be_bytes(word[24..32].try_into().unwrap()))
}

pub fn balance_of_call(who: &Addr) -> Vec<u8> {
    let mut d = selector("balanceOf(address)");
    word_addr(&mut d, who);
    d
}

pub fn allowance_call(owner: &Addr, spender: &Addr) -> Vec<u8> {
    let mut d = selector("allowance(address,address)");
    word_addr(&mut d, owner);
    word_addr(&mut d, spender);
    d
}

/// `approve(spender, 2^256 - 1)`: once per token and address.
pub fn approve_max_call(spender: &Addr) -> Vec<u8> {
    let mut d = selector("approve(address,uint256)");
    word_addr(&mut d, spender);
    d.extend_from_slice(&[0xff; 32]);
    d
}

pub fn transfer_call(to: &Addr, amount: u64) -> Vec<u8> {
    let mut d = selector("transfer(address,uint256)");
    word_addr(&mut d, to);
    word_u64(&mut d, amount);
    d
}

/// The terms of a RequantHtlc lock; its id hashes them all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub token: Addr,
    pub sender: Addr,
    pub receiver: Addr,
    pub amount: u64,
    pub hash: [u8; 32],
    /// Unix seconds: claims before, refunds from.
    pub timeout: u64,
}

impl Terms {
    fn words(&self, d: &mut Vec<u8>) {
        word_addr(d, &self.token);
        word_addr(d, &self.sender);
        word_addr(d, &self.receiver);
        word_u64(d, self.amount);
        d.extend_from_slice(&self.hash);
        word_u64(d, self.timeout);
    }

    /// `lockId(...)`: keccak256(abi.encode(token, sender, receiver, amount, hash, timeout)).
    pub fn id(&self) -> [u8; 32] {
        let mut d = Vec::new();
        self.words(&mut d);
        keccak(&d)
    }

    pub fn lock_call(&self) -> Vec<u8> {
        let mut d = selector("lock(address,address,uint256,bytes32,uint64)");
        word_addr(&mut d, &self.token);
        word_addr(&mut d, &self.receiver);
        word_u64(&mut d, self.amount);
        d.extend_from_slice(&self.hash);
        word_u64(&mut d, self.timeout);
        d
    }

    pub fn claim_call(&self, secret: &[u8; 32]) -> Vec<u8> {
        let mut d = selector("claim(address,address,address,uint256,bytes32,uint64,bytes32)");
        self.words(&mut d);
        d.extend_from_slice(secret);
        d
    }

    pub fn refund_call(&self) -> Vec<u8> {
        let mut d = selector("refund(address,address,address,uint256,bytes32,uint64)");
        self.words(&mut d);
        d
    }

    pub fn state_call(&self) -> Vec<u8> {
        let mut d = selector("states(bytes32)");
        d.extend_from_slice(&self.id());
        d
    }

    pub fn json(&self) -> Value {
        json!({"token": to_base58(&self.token), "sender": to_base58(&self.sender),
               "receiver": to_base58(&self.receiver), "amount": self.amount, "hash": hex(&self.hash),
               "timeout": self.timeout, "id": hex(&self.id())})
    }

    pub fn from_json(v: &Value) -> Result<Terms, String> {
        let a = |k: &str| parse(v[k].as_str().ok_or(format!("{k}: a TRON address"))?);
        Ok(Terms {
            token: a("token")?,
            sender: a("sender")?,
            receiver: a("receiver")?,
            amount: v["amount"].as_u64().ok_or("amount: a number")?,
            hash: v["hash"]
                .as_str()
                .and_then(|h| unhex(h).ok())
                .and_then(|b| b.try_into().ok())
                .ok_or("hash: 64 hex digits")?,
            timeout: v["timeout"].as_u64().ok_or("timeout: unix seconds")?,
        })
    }
}

/// The state of a lock, as `states(id)` returns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState {
    None,
    Open,
    Claimed,
    Refunded,
}

impl LockState {
    pub fn name(self) -> &'static str {
        match self {
            LockState::None => "none",
            LockState::Open => "open",
            LockState::Claimed => "claimed",
            LockState::Refunded => "refunded",
        }
    }
}

// ---- transactions -----------------------------------------------------------------------------------

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn field_varint(out: &mut Vec<u8>, field: u64, v: u64) {
    varint(out, field << 3);
    varint(out, v);
}

fn field_bytes(out: &mut Vec<u8>, field: u64, b: &[u8]) {
    varint(out, field << 3 | 2);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// The block a transaction refers to (TAPOS) and the time it is made at.
#[derive(Clone, Copy, Debug)]
pub struct RefBlock {
    pub number: u64,
    pub id: [u8; 32],
    pub timestamp_ms: u64,
}

/// `Transaction.raw` with one contract: `kind` 1 is TransferContract, 31 TriggerSmartContract.
fn raw(block: &RefBlock, kind: u64, type_name: &str, parameter: &[u8], fee_limit: u64) -> Vec<u8> {
    let mut any = Vec::new();
    field_bytes(&mut any, 1, format!("type.googleapis.com/protocol.{type_name}").as_bytes());
    field_bytes(&mut any, 2, parameter);
    let mut contract = Vec::new();
    field_varint(&mut contract, 1, kind);
    field_bytes(&mut contract, 2, &any);
    let mut r = Vec::new();
    field_bytes(&mut r, 1, &block.number.to_be_bytes()[6..8]);
    field_bytes(&mut r, 4, &block.id[8..16]);
    field_varint(&mut r, 8, block.timestamp_ms + 10 * 60 * 1000);
    field_bytes(&mut r, 11, &contract);
    field_varint(&mut r, 14, block.timestamp_ms);
    if fee_limit > 0 {
        field_varint(&mut r, 18, fee_limit);
    }
    r
}

/// A contract call paying no TRX, spending at most `fee_limit` sun on energy.
pub fn trigger(block: &RefBlock, owner: &Addr, contract: &Addr, data: &[u8], fee_limit: u64) -> Vec<u8> {
    let mut p = Vec::new();
    field_bytes(&mut p, 1, owner);
    field_bytes(&mut p, 2, contract);
    field_bytes(&mut p, 4, data);
    raw(block, 31, "TriggerSmartContract", &p, fee_limit)
}

/// A TRX transfer of `sun` (millionths of a TRX).
pub fn transfer(block: &RefBlock, owner: &Addr, to: &Addr, sun: u64) -> Vec<u8> {
    let mut p = Vec::new();
    field_bytes(&mut p, 1, owner);
    field_bytes(&mut p, 2, to);
    field_varint(&mut p, 3, sun);
    raw(block, 1, "TransferContract", &p, 0)
}

/// Stake 2.0, energy only (ResourceCode ENERGY = 1): stake `sun` of the owner's TRX for energy.
pub fn freeze_energy(block: &RefBlock, owner: &Addr, sun: u64) -> Vec<u8> {
    let mut p = Vec::new();
    field_bytes(&mut p, 1, owner);
    field_varint(&mut p, 2, sun);
    field_varint(&mut p, 3, 1);
    raw(block, 54, "FreezeBalanceV2Contract", &p, 0)
}

/// Lend the energy of `sun` staked TRX to `receiver` (`undo`: take it back).
pub fn delegate_energy(block: &RefBlock, owner: &Addr, receiver: &Addr, sun: u64, undo: bool) -> Vec<u8> {
    let mut p = Vec::new();
    field_bytes(&mut p, 1, owner);
    field_varint(&mut p, 2, 1);
    field_varint(&mut p, 3, sun);
    field_bytes(&mut p, 4, receiver);
    if undo {
        raw(block, 58, "UnDelegateResourceContract", &p, 0)
    } else {
        raw(block, 57, "DelegateResourceContract", &p, 0)
    }
}

/// Energy a USDT lock may take from a swap's address: the approval (once per address; 22,688 on Nile)
/// and the lock (43,638 on Nile; more on the main network, where USDT costs more), with room to spare.
pub const APPROVE_ENERGY: u64 = 30_000;
pub const LOCK_ENERGY: u64 = 70_000;
/// Bandwidth of the approval and the lock, should the address's free bandwidth be used up (sun).
pub const LOCK_BANDWIDTH_SUN: u64 = 1_000_000;

pub fn txid(raw: &[u8]) -> [u8; 32] {
    crate::swap::sha256(raw)
}

/// The signed transaction (protobuf `Transaction`) and its id.
pub fn sign(raw: &[u8], secret: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), String> {
    let id = txid(raw);
    let sk = SecretKey::from_slice(secret).map_err(|e| format!("TRON key: {e}"))?;
    let (rec, compact) = Secp256k1::new().sign_ecdsa_recoverable(&Message::from_digest(id), &sk).serialize_compact();
    let mut sig = compact.to_vec();
    sig.push(rec.to_i32() as u8);
    let mut t = Vec::new();
    field_bytes(&mut t, 1, raw);
    field_bytes(&mut t, 2, &sig);
    Ok((t, id))
}

// ---- the API ----------------------------------------------------------------------------------------

/// A TRON node's HTTP API (`/wallet/...` for the newest state, `/walletsolidity/...` for the
/// irreversible one, about 19 blocks or a minute behind).
pub struct Tron {
    api: String,
    agent: ureq::Agent,
}

impl Tron {
    pub fn new(api: &str) -> Tron {
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build();
        Tron { api: api.trim_end_matches('/').to_string(), agent }
    }

    fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let text = self
            .agent
            .post(&format!("{}{path}", self.api))
            .set("content-type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| format!("TRON API: {e}"))?
            .into_string()
            .map_err(|e| format!("TRON API: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("TRON API: {e}"))
    }

    pub fn now_block(&self) -> Result<RefBlock, String> {
        let b = self.post("/wallet/getnowblock", json!({}))?;
        let h = &b["block_header"]["raw_data"];
        Ok(RefBlock {
            number: h["number"].as_u64().ok_or("TRON API: no block number")?,
            id: b["blockID"]
                .as_str()
                .and_then(|s| unhex(s).ok())
                .and_then(|v| v.try_into().ok())
                .ok_or("TRON API: no block id")?,
            timestamp_ms: h["timestamp"].as_u64().ok_or("TRON API: no block time")?,
        })
    }

    /// The chain's time (the newest block's), in unix seconds.
    pub fn now(&self) -> Result<u64, String> {
        Ok(self.now_block()?.timestamp_ms / 1000)
    }

    /// TRX balance in sun; 0 for an account that does not exist yet.
    pub fn trx_balance(&self, who: &Addr) -> Result<u64, String> {
        let a = self.post("/wallet/getaccount", json!({"address": to_base58(who), "visible": true}))?;
        Ok(a["balance"].as_u64().unwrap_or(0))
    }

    /// A read-only contract call; `solid` reads the irreversible state.
    pub fn call(&self, owner: &Addr, contract: &Addr, data: &[u8], solid: bool) -> Result<Vec<u8>, String> {
        let path = if solid { "/walletsolidity/triggerconstantcontract" } else { "/wallet/triggerconstantcontract" };
        let r = self.post(
            path,
            json!({"owner_address": to_base58(owner), "contract_address": to_base58(contract), "data": hex(data),
                   "visible": true}),
        )?;
        let out = r["constant_result"][0].as_str().and_then(|s| unhex(s).ok()).unwrap_or_default();
        if r["result"]["result"] != json!(true) || r["transaction"]["ret"][0]["ret"] == json!("FAILED") {
            return Err(format!("contract call refused: {}", revert_reason(&out)));
        }
        Ok(out)
    }

    pub fn token_balance(&self, token: &Addr, who: &Addr) -> Result<u64, String> {
        decode_u64(&self.call(who, token, &balance_of_call(who), false)?)
    }

    pub fn allowance(&self, token: &Addr, owner: &Addr, spender: &Addr) -> Result<bool, String> {
        let w = self.call(owner, token, &allowance_call(owner, spender), false)?;
        Ok(w.len() >= 32 && w[..24].iter().any(|b| *b != 0))
    }

    pub fn lock_state(&self, htlc: &Addr, terms: &Terms, solid: bool) -> Result<LockState, String> {
        let w = self.call(&terms.sender, htlc, &terms.state_call(), solid)?;
        Ok(match decode_u64(&w)? {
            0 => LockState::None,
            1 => LockState::Open,
            2 => LockState::Claimed,
            3 => LockState::Refunded,
            n => return Err(format!("unknown lock state {n}")),
        })
    }

    /// Relays a signed transaction; one the node already has counts as relayed.
    pub fn broadcast(&self, signed: &[u8]) -> Result<(), String> {
        let r = self.post("/wallet/broadcasthex", json!({"transaction": hex(signed)}))?;
        if r["result"] == json!(true) || r["code"] == json!("DUP_TRANSACTION_ERROR") {
            return Ok(());
        }
        let msg = r["message"].as_str().and_then(|m| unhex(m).ok()).map(|m| String::from_utf8_lossy(&m).into_owned());
        Err(format!("TRON: {} {}", r["code"].as_str().unwrap_or("refused"), msg.unwrap_or_default()))
    }

    /// Builds, signs and relays a contract call; the transaction id and the signed transaction.
    pub fn send_call(
        &self,
        secret: &[u8; 32],
        contract: &Addr,
        data: &[u8],
        fee_limit: u64,
    ) -> Result<(String, Vec<u8>), String> {
        let owner = address_of(secret)?;
        let (signed, id) = sign(&trigger(&self.now_block()?, &owner, contract, data, fee_limit), secret)?;
        self.broadcast(&signed)?;
        Ok((hex(&id), signed))
    }

    pub fn send_trx(&self, secret: &[u8; 32], to: &Addr, sun: u64) -> Result<String, String> {
        let owner = address_of(secret)?;
        self.send_raw(secret, &transfer(&self.now_block()?, &owner, to, sun))
    }

    /// Signs and relays a transaction built here; its id.
    pub fn send_raw(&self, secret: &[u8; 32], raw: &[u8]) -> Result<String, String> {
        let (signed, id) = sign(raw, secret)?;
        self.broadcast(&signed)?;
        Ok(hex(&id))
    }

    pub fn exists(&self, who: &Addr) -> Result<bool, String> {
        let a = self.post("/wallet/getaccount", json!({"address": to_base58(who), "visible": true}))?;
        Ok(a.as_object().is_some_and(|o| !o.is_empty()))
    }

    /// The address's energy left now (its own staked and what others lend it).
    pub fn energy(&self, who: &Addr) -> Result<u64, String> {
        let r = self.post("/wallet/getaccountresource", json!({"address": to_base58(who), "visible": true}))?;
        Ok(r["EnergyLimit"].as_u64().unwrap_or(0).saturating_sub(r["EnergyUsed"].as_u64().unwrap_or(0)))
    }

    /// Sun of staked TRX that gives `energy` a day at the network's current ratio, rounded up to whole TRX
    /// (the totals come with any account's resources: `owner`'s).
    pub fn stake_for_energy(&self, owner: &Addr, energy: u64) -> Result<u64, String> {
        let r = self.post("/wallet/getaccountresource", json!({"address": to_base58(owner), "visible": true}))?;
        let (limit, weight) =
            (r["TotalEnergyLimit"].as_u64().unwrap_or(0), r["TotalEnergyWeight"].as_u64().unwrap_or(0));
        if limit == 0 || weight == 0 {
            return Err("TRON API: no energy totals".into());
        }
        Ok(((energy as u128 * weight as u128).div_ceil(limit as u128) as u64) * 1_000_000)
    }

    /// Sun of the owner's staked TRX whose energy it can lend now.
    pub fn can_delegate(&self, owner: &Addr) -> Result<u64, String> {
        let r = self.post(
            "/wallet/getcandelegatedmaxsize",
            json!({"owner_address": to_base58(owner), "type": 1, "visible": true}),
        )?;
        Ok(r["max_size"].as_u64().unwrap_or(0))
    }

    /// A chain parameter (`getEnergyFee`: sun burned per energy unit, `getTransactionFee`: per byte).
    pub fn parameter(&self, key: &str) -> Result<u64, String> {
        let r = self.post("/wallet/getchainparameters", json!({}))?;
        r["chainParameter"]
            .as_array()
            .and_then(|ps| ps.iter().find(|p| p["key"] == json!(key)))
            .and_then(|p| p["value"].as_u64())
            .ok_or(format!("TRON API: no parameter {key}"))
    }

    /// Whether an address can pay for `energy` now: with energy, or with TRX to burn for it.
    pub fn can_pay(&self, who: &Addr, energy: u64) -> Result<bool, String> {
        let have = self.energy(who)?;
        if have >= energy {
            return Ok(self.trx_balance(who)? >= LOCK_BANDWIDTH_SUN / 2);
        }
        Ok(self.trx_balance(who)? >= (energy - have) * self.parameter("getEnergyFee")? + LOCK_BANDWIDTH_SUN)
    }

    /// Whether a transaction is in an irreversible block, and whether it succeeded there: `None` while it
    /// is not (yet); the energy and TRX burned with the outcome.
    pub fn outcome(&self, txid: &str) -> Result<Option<Outcome>, String> {
        let r = self.post("/walletsolidity/gettransactioninfobyid", json!({"value": txid}))?;
        if r["blockNumber"].is_null() {
            return Ok(None);
        }
        let receipt = &r["receipt"];
        Ok(Some(Outcome {
            ok: receipt["result"].as_str().is_none_or(|s| s == "SUCCESS") && r["result"] != json!("FAILED"),
            energy: receipt["energy_usage_total"].as_u64().unwrap_or(0),
            fee_sun: r["fee"].as_u64().unwrap_or(0),
            block: r["blockNumber"].as_u64().unwrap_or(0),
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub energy: u64,
    pub fee_sun: u64,
    pub block: u64,
}

/// The message of a Solidity `require` (an `Error(string)`), or the raw bytes in hex.
pub fn revert_reason(out: &[u8]) -> String {
    if out.len() >= 68 && out[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        let n = decode_u64(&out[36..68]).unwrap_or(0) as usize;
        if let Some(m) = out.get(68..68 + n) {
            return String::from_utf8_lossy(m).into_owned();
        }
    }
    if out.is_empty() {
        "no reason given".into()
    } else {
        hex(out)
    }
}

/// Token units (USDT: millionths) as a decimal.
pub fn format_units(units: u64) -> String {
    format!("{}.{:06}", units / 1_000_000, units % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_known_ids() {
        // a key, its address and a lock id as tronpy and eth_abi compute them
        let a = address_of(&[1u8; 32]).unwrap();
        assert_eq!(to_base58(&a), "TCNkawTmcQgYSU8nP8cHswT1QPjharxJr7");
        assert_eq!(parse(&to_base58(&a)).unwrap(), a);
        let terms = Terms {
            token: parse("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf").unwrap(),
            sender: parse("TRED2Ydeh7o4D4uNW6S11L1JKmDvtwesWe").unwrap(),
            receiver: parse("TYfBAJYoXxJnVdnF8Gk3CpNZkPvT6ohg8T").unwrap(),
            amount: 5_000_000,
            hash: [9; 32],
            timeout: 1_791_724_224,
        };
        assert_eq!(hex(&terms.id()), "6e3ea34331c5c970dc5330003d999b949daaf095b157ae96cf7586c213781682");
        assert_eq!(Terms::from_json(&terms.json()), Ok(terms));
        assert!(parse("1BoatSLRHtKNngkdXEeobR76b53LETtpyT").is_err(), "a Bitcoin address");
        let usdt = parse("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf").unwrap();
        assert_eq!(to_base58(&usdt), "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf");
        // selectors match the contract's
        assert_eq!(hex(&selector("transfer(address,uint256)")), "a9059cbb");
        assert_eq!(hex(&selector("balanceOf(address)")), "70a08231");
    }

    #[test]
    fn protobuf_matches_a_known_transaction() {
        // a field-by-field rebuild of how tronpy encodes a TriggerSmartContract
        let block = RefBlock { number: 0x0446_82dd, id: [7; 32], timestamp_ms: 1_791_720_000_000 };
        let owner = parse("TYfBAJYoXxJnVdnF8Gk3CpNZkPvT6ohg8T").unwrap();
        let usdt = parse("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf").unwrap();
        let r = trigger(&block, &owner, &usdt, &transfer_call(&owner, 5), 100_000_000);
        assert_eq!(&r[..4], &[0x0a, 0x02, 0x82, 0xdd], "ref_block_bytes: the low two bytes of the number");
        assert_eq!(&r[4..6], &[0x22, 0x08], "ref_block_hash: eight bytes");
        assert_eq!(&r[6..14], &[7; 8]);
        let type_url = b"type.googleapis.com/protocol.TriggerSmartContract";
        assert!(r.windows(type_url.len()).any(|w| w == type_url));
        let (signed, id) = sign(&r, &[1; 32]).unwrap();
        assert_eq!(id, txid(&r));
        assert_eq!(signed.len(), r.len() + 2 + 2 + 65 + (r.len() >= 128) as usize);
    }

    #[test]
    fn revert_reasons() {
        let mut out = vec![0x08, 0xc3, 0x79, 0xa0];
        out.extend_from_slice(&[0; 31]);
        out.push(32);
        out.extend_from_slice(&[0; 31]);
        out.push(6);
        out.extend_from_slice(b"secret");
        out.extend_from_slice(&[0; 26]);
        assert_eq!(revert_reason(&out), "secret");
        assert_eq!(revert_reason(&[]), "no reason given");
    }
}
