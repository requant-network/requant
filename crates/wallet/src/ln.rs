//! The Lightning side of RQT<->BTC swaps: a hold invoice with the taker's hash (SWAPS.md §1).
//!
//! The maker's LND holds the taker's payment without being able to take it (only the taker knows the
//! secret), locks the RQT, and settles the invoice with the secret the taker's Requant claim reveals; or
//! cancels it, and the payment goes back to the taker by itself. The taker checks the invoice
//! (`decode_invoice`): its payment hash must be the taker's own, or the maker could be paid without locking.

use serde_json::{json, Value};

/// A BOLT11 invoice, as far as the taker needs it.
#[derive(Debug, PartialEq, Eq)]
pub struct Invoice {
    /// lnbc (bitcoin), lntb (testnet), lntbs (signet), lnbcrt (regtest)
    pub prefix: String,
    /// Millisatoshis, if the invoice names an amount.
    pub msat: Option<u64>,
    pub payment_hash: [u8; 32],
    pub timestamp: u64,
    /// Seconds from `timestamp` (3600 when absent).
    pub expiry: u64,
    /// Blocks the payee needs at the end of the route (18 when absent).
    pub min_final_cltv: u64,
}

const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const G: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ *v as u32;
        for (i, g) in G.iter().enumerate() {
            if top >> i & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The prefix of a network: `bitcoin`, `testnet`/`testnet4`, `signet`, `regtest`.
pub fn prefix_of(btc_network: &str) -> &'static str {
    match btc_network {
        "bitcoin" | "main" => "lnbc",
        "signet" => "lntbs",
        "regtest" => "lnbcrt",
        _ => "lntb",
    }
}

/// Decode a BOLT11 invoice (checksum, amount, payment hash, expiry, final CLTV). The signature is not
/// checked: the taker does not care who is paid, only that the payment is locked by its own hash.
pub fn decode_invoice(s: &str) -> Result<Invoice, String> {
    let s = s.trim().to_ascii_lowercase();
    let s = s.strip_prefix("lightning:").unwrap_or(&s);
    let sep = s.rfind('1').ok_or("not an invoice")?;
    let (hrp, data) = (&s[..sep], &s[sep + 1..]);
    if !hrp.starts_with("ln") || data.len() < 104 + 7 + 6 {
        return Err("not a Lightning invoice".into());
    }
    let data: Vec<u8> =
        data.chars().map(|c| CHARSET.find(c).map(|i| i as u8)).collect::<Option<_>>().ok_or("bad character")?;
    let mut check: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    check.push(0);
    check.extend(hrp.bytes().map(|b| b & 31));
    check.extend(&data);
    if polymod(&check) != 1 {
        return Err("bad invoice checksum".into());
    }
    // the network prefix, then an optional amount: digits and a multiplier
    let body = &hrp[2..];
    let split = body.find(|c: char| c.is_ascii_digit()).unwrap_or(body.len());
    let (net, amount) = body.split_at(split);
    let prefix = format!("ln{net}");
    let msat = if amount.is_empty() {
        None
    } else {
        let (digits, mult) = match amount.chars().last().unwrap() {
            c @ ('m' | 'u' | 'n' | 'p') => (&amount[..amount.len() - 1], Some(c)),
            _ => (amount, None),
        };
        let n: u64 = digits.parse().map_err(|_| "bad invoice amount")?;
        // millisatoshis per unit: 1 BTC = 10^11 msat
        let msat = match mult {
            None => n.checked_mul(100_000_000_000),
            Some('m') => n.checked_mul(100_000_000),
            Some('u') => n.checked_mul(100_000),
            Some('n') => n.checked_mul(100),
            Some('p') => n.is_multiple_of(10).then_some(n / 10),
            _ => None,
        };
        Some(msat.ok_or("bad invoice amount")?)
    };
    let data = &data[..data.len() - 6 - 104]; // checksum and signature
    let word = |from: usize, len: usize| -> u64 { data[from..from + len].iter().fold(0u64, |a, &b| a << 5 | b as u64) };
    let timestamp = word(0, 7);
    let (mut k, mut hash, mut expiry, mut cltv) = (7usize, None, 3600, 18);
    while k + 3 <= data.len() {
        let tag = data[k];
        let len = word(k + 1, 2) as usize;
        let field = data.get(k + 3..k + 3 + len).ok_or("truncated invoice")?;
        match tag {
            1 if len == 52 => {
                // 52 groups of 5 bits: 256 bits of hash and 4 of padding
                let mut bits: Vec<u8> = Vec::new();
                let (mut acc, mut n) = (0u32, 0);
                for v in field {
                    acc = acc << 5 | *v as u32;
                    n += 5;
                    while n >= 8 {
                        n -= 8;
                        bits.push((acc >> n) as u8);
                    }
                }
                hash = Some(<[u8; 32]>::try_from(&bits[..32]).unwrap());
            }
            6 => expiry = word(k + 3, len),
            24 => cltv = word(k + 3, len),
            _ => {}
        }
        k += 3 + len;
    }
    Ok(Invoice {
        prefix,
        msat,
        payment_hash: hash.ok_or("the invoice has no payment hash")?,
        timestamp,
        expiry,
        min_final_cltv: cltv,
    })
}

/// The maker's LND over REST (plain HTTP on the same host; `--no-rest-tls`), with a macaroon.
pub struct Lnd {
    addr: std::net::SocketAddr,
    macaroon: String,
}

fn b64(data: &[u8]) -> String {
    crate::btc::base64(data)
}

impl Lnd {
    pub fn new(addr: &str, macaroon: &[u8]) -> Result<Lnd, String> {
        use std::net::ToSocketAddrs;
        let addr = addr.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("lnd: no address")?;
        Ok(Lnd { addr, macaroon: requant_node::rpc::hex(macaroon) })
    }

    fn call(&self, verb: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        use std::io::{Read, Write};
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let mut s = std::net::TcpStream::connect_timeout(&self.addr, std::time::Duration::from_secs(15))
            .map_err(|e| format!("lnd: {e}"))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(60))).map_err(|e| e.to_string())?;
        write!(
            s,
            "{verb} {path} HTTP/1.1\r\nHost: {}\r\nGrpc-Metadata-macaroon: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            self.macaroon,
            body.len()
        )
        .map_err(|e| e.to_string())?;
        let mut resp = String::new();
        s.read_to_string(&mut resp).map_err(|e| format!("lnd: {e}"))?;
        let status = resp.split(' ').nth(1).and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);
        let text = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        if status != 200 {
            return Err(format!(
                "lnd {path}: {}",
                v["message"].as_str().unwrap_or(text).chars().take(200).collect::<String>()
            ));
        }
        Ok(v)
    }

    /// A hold invoice for `sats` locked by `hash`, payable for `expiry` seconds, asking `cltv` blocks at
    /// the end of the route; the BOLT11 string.
    pub fn add_hold_invoice(
        &self,
        hash: &[u8; 32],
        sats: u64,
        expiry: u64,
        cltv: u64,
        memo: &str,
    ) -> Result<String, String> {
        let v = self.call(
            "POST",
            "/v2/invoices/hodl",
            Some(json!({"hash": b64(hash), "value": sats.to_string(),
            "expiry": expiry.to_string(), "cltv_expiry": cltv.to_string(), "memo": memo})),
        )?;
        v["payment_request"].as_str().map(str::to_string).ok_or("lnd: no payment request".into())
    }

    /// `(state, satoshis paid, lowest expiry height of the held HTLCs)`; state is OPEN, ACCEPTED,
    /// SETTLED or CANCELED.
    pub fn invoice(&self, hash: &[u8; 32]) -> Result<(String, u64, Option<u64>), String> {
        let v = self.call("GET", &format!("/v1/invoice/{}", requant_node::rpc::hex(hash)), None)?;
        let paid = v["amt_paid_sat"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
        let expiry = v["htlcs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|h| h["state"].as_str() == Some("ACCEPTED"))
            .filter_map(|h| h["expiry_height"].as_u64())
            .min();
        Ok((v["state"].as_str().unwrap_or("").to_string(), paid, expiry))
    }

    pub fn settle(&self, preimage: &[u8; 32]) -> Result<(), String> {
        self.call("POST", "/v2/invoices/settle", Some(json!({"preimage": b64(preimage)}))).map(|_| ())
    }

    pub fn cancel(&self, hash: &[u8; 32]) -> Result<(), String> {
        self.call("POST", "/v2/invoices/cancel", Some(json!({"payment_hash": b64(hash)}))).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_regtest_hold_invoice_from_lnd() {
        // made by LND 0.21.4 on regtest: 2000 sat, expiry 600 s, cltv 80
        let s = "lnbcrt20u1p4vkktzpp5w64y8sx4995tkul26nycecsfztt8wt9fx2tq5f8jahzswr8kxg2sdqdwfchggrnwashqcqzzsxqzjcsp5cx4566nkltgkt350nc4uccaga7f0er4lhen2u8x847d9d3ytvraq9qxpqysgqjl2atleer4e42lcxm0r4z570czq6p43dk9fkqgzh4y6fdl6t42tp64ea2t056dqpatm32nynkj9gsxr9c4k6tsat8wmvnc60gp3unscpveud5m";
        let i = decode_invoice(s).unwrap();
        assert_eq!(i.prefix, "lnbcrt");
        assert_eq!(i.msat, Some(2_000_000));
        assert_eq!(
            requant_node::rpc::hex(&i.payment_hash),
            "76aa43c0d52968bb73ead4c98ce20912d6772ca932960a24f2edc5070cf63215"
        );
        assert_eq!((i.expiry, i.min_final_cltv), (600, 80));
        // one character changed: the checksum fails
        let bad = s.replacen("w64y", "w64z", 1);
        assert!(decode_invoice(&bad).is_err());
        assert_eq!(prefix_of("regtest"), "lnbcrt");
        assert_eq!(prefix_of("signet"), "lntbs");
    }
}
