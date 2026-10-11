//! RQT<->BTC atomic swaps (SWAPS.md §1): a taker buys RQT with BTC from a maker.
//!
//! 1. The taker picks a 32-byte secret and asks the maker for a swap (`swap_create`): the amount of RQT,
//!    the secret's SHA-256, the taker's Bitcoin refund key and the Requant address to receive at.
//! 2. The maker answers with a Bitcoin HTLC (claim: the maker's key with the secret; refund: the taker's
//!    key from `btc_timeout`) and its price. The taker pays that P2WSH address from any Bitcoin wallet.
//! 3. Once the payment has the maker's confirmations, the maker locks the RQT in a Requant HTLC with the
//!    same hash (claim: the taker; refund: the maker from `rqt_timeout`).
//! 4. The taker claims the RQT, which reveals the secret on Requant; the maker reads it there and claims
//!    the BTC.
//!
//! Who is protected by what:
//! - The taker reveals the secret only by taking the RQT. If the maker never locks them, the taker takes
//!   the BTC back from `btc_timeout`.
//! - The maker is protected by the order of the time locks: the Requant HTLC expires long before the
//!   Bitcoin one, so a secret revealed at the last Requant moment still leaves time to claim the BTC.
//!   The maker locks RQT only while at least `MIN_BTC_BLOCKS_LEFT` Bitcoin blocks are left.

use crate::btc;
use crate::contracts::Condition;
use bitcoin::hashes::Hash as _;
use requant_consensus::tx::{Htlc as RqtHtlc, Tx, Unlock};
use requant_node::rpc::{hex, unhex};
use serde_json::{json, Value};

/// Bitcoin blocks (about a day) from the swap to the taker's refund.
pub const BTC_TIMEOUT_BLOCKS: u32 = 144;
/// Requant blocks (about six hours at 60 s) from the maker's lock to its refund.
pub const RQT_TIMEOUT_BLOCKS: u64 = 360;
/// The maker locks RQT only while this many Bitcoin blocks (about twelve hours) are left to the taker's
/// refund: twice the Requant time lock, so a late claim of the RQT still leaves time to claim the BTC.
pub const MIN_BTC_BLOCKS_LEFT: u32 = 72;

// the Requant lock (360 min) fits twice into what the maker requires to be left on Bitcoin (72 x 10 min)
const _: () = assert!(RQT_TIMEOUT_BLOCKS * 60 * 2 <= MIN_BTC_BLOCKS_LEFT as u64 * 600);
const _: () = assert!(MIN_BTC_BLOCKS_LEFT < BTC_TIMEOUT_BLOCKS);

/// Bitcoin confirmations the maker waits for before it locks RQT, by the swap's size in satoshis.
pub fn btc_confirmations(sats: u64) -> u32 {
    match sats {
        0..=1_000_000 => 1,          // up to 0.01 BTC
        1_000_001..=10_000_000 => 3, // up to 0.1 BTC
        _ => 6,
    }
}

/// The satoshis `rqt_atoms` cost at `sats_per_rqt` (rounded up).
pub fn price(rqt_atoms: u64, sats_per_rqt: u64) -> u64 {
    ((rqt_atoms as u128 * sats_per_rqt as u128).div_ceil(100_000_000)) as u64
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    bitcoin::hashes::sha256::Hash::hash(data).to_byte_array()
}

fn h32(v: &Value, what: &str) -> Result<[u8; 32], String> {
    v.as_str()
        .and_then(|s| unhex(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or(format!("{what}: expected 64 hex digits"))
}

fn pubkey(v: &Value, what: &str) -> Result<bitcoin::PublicKey, String> {
    v.as_str().and_then(|s| s.parse().ok()).ok_or(format!("{what}: expected a compressed public key"))
}

/// The Bitcoin HTLC of a swap, from its JSON.
pub fn btc_htlc_from(v: &Value) -> Result<btc::Htlc, String> {
    Ok(btc::Htlc {
        hash: h32(&v["hash"], "hash")?,
        claim: pubkey(&v["claim"], "claim")?,
        refund: pubkey(&v["refund"], "refund")?,
        timeout: v["timeout"].as_u64().and_then(|t| u32::try_from(t).ok()).ok_or("timeout: expected a height")?,
    })
}

pub fn btc_htlc_json(h: &btc::Htlc, net: bitcoin::Network) -> Value {
    json!({"hash": hex(&h.hash), "claim": h.claim.to_string(), "refund": h.refund.to_string(), "timeout": h.timeout,
           "address": h.address(net).to_string()})
}

/// The Requant HTLC of a swap, from its JSON (as `rqt_htlc` in the maker's status).
pub fn rqt_htlc_from(v: &Value) -> Result<RqtHtlc, String> {
    Ok(RqtHtlc {
        hash: h32(&v["hash"], "hash")?,
        claim: h32(&v["claim"], "claim")?,
        refund: h32(&v["refund"], "refund")?,
        timeout: v["timeout"].as_u64().ok_or("timeout: expected a height")?,
    })
}

pub fn rqt_htlc_json(h: &RqtHtlc) -> Value {
    json!({"hash": hex(&h.hash), "claim": hex(&h.claim), "refund": hex(&h.refund), "timeout": h.timeout,
           "owner": hex(&Condition::Htlc(*h).owner())})
}

/// The secret a Requant transfer revealed by claiming `htlc`.
pub fn revealed_on_requant(tx: &Tx, htlc: &RqtHtlc) -> Option<[u8; 32]> {
    let Tx::Transfer { inputs, .. } = tx else { return None };
    inputs.iter().find_map(|i| match i.unlock {
        Unlock::HtlcClaim { htlc: h, preimage } if h == *htlc && sha256(&preimage) == htlc.hash => Some(preimage),
        _ => None,
    })
}

/// What the taker checks in the maker's answer before paying anything: the Bitcoin HTLC is for the
/// taker's own hash and refund key and its address is the one these parameters give; the time lock leaves
/// the maker time to lock RQT; the price is the one asked for.
pub fn check_offer(
    offer: &Value,
    hash: &[u8; 32],
    refund: &bitcoin::PublicKey,
    net: bitcoin::Network,
    max_sats: u64,
) -> Result<btc::Htlc, String> {
    let h = btc_htlc_from(&offer["btc_htlc"])?;
    if h.hash != *hash || h.refund != *refund {
        return Err("the maker's HTLC is not for this swap's secret and refund key".into());
    }
    if offer["btc_htlc"]["address"].as_str() != Some(h.address(net).to_string().as_str()) {
        return Err("the maker's address does not match its HTLC".into());
    }
    let sats = offer["btc_sats"].as_u64().ok_or("btc_sats missing")?;
    if sats == 0 || sats > max_sats {
        return Err(format!("the maker asks {sats} satoshis, more than the {max_sats} allowed"));
    }
    Ok(h)
}

/// What the taker checks before claiming: the Requant HTLC pays the taker with the swap's hash.
pub fn check_lock(lock: &RqtHtlc, hash: &[u8; 32], claim: &[u8; 32]) -> Result<(), String> {
    if lock.hash != *hash || lock.claim != *claim {
        return Err("the maker's Requant HTLC is not for this swap".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prices_confirmations_and_time_locks() {
        assert_eq!(price(100_000_000, 2_000), 2_000);
        assert_eq!(price(1, 2_000), 1);
        assert_eq!(price(150_000_000, 3), 5);
        assert_eq!(btc_confirmations(500_000), 1);
        assert_eq!(btc_confirmations(5_000_000), 3);
        assert_eq!(btc_confirmations(50_000_000), 6);
    }

    #[test]
    fn the_taker_checks_the_offer() {
        let net = bitcoin::Network::Regtest;
        let hash = sha256(&[9; 32]);
        let mine = btc::public_key(&[4; 32]).unwrap();
        let h = btc::Htlc { hash, claim: btc::public_key(&[3; 32]).unwrap(), refund: mine, timeout: 500 };
        let offer = json!({"btc_htlc": btc_htlc_json(&h, net), "btc_sats": 2000});
        assert_eq!(check_offer(&offer, &hash, &mine, net, 2000), Ok(h));
        assert!(check_offer(&offer, &hash, &mine, net, 1999).is_err(), "more than asked");
        assert!(check_offer(&offer, &sha256(&[8; 32]), &mine, net, 2000).is_err(), "another secret");
        assert!(
            check_offer(&offer, &hash, &btc::public_key(&[5; 32]).unwrap(), net, 2000).is_err(),
            "another refund key"
        );
        let mut forged = offer.clone();
        forged["btc_htlc"]["address"] = json!(btc::Htlc { timeout: 501, ..h }.address(net).to_string());
        assert!(check_offer(&forged, &hash, &mine, net, 2000).is_err(), "an address of other parameters");
        let lock = RqtHtlc { hash, claim: [1; 32], refund: [2; 32], timeout: 9 };
        assert!(check_lock(&lock, &hash, &[1; 32]).is_ok());
        assert!(check_lock(&lock, &hash, &[2; 32]).is_err());
        assert_eq!(rqt_htlc_from(&rqt_htlc_json(&lock)), Ok(lock));
    }
}
