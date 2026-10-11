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
