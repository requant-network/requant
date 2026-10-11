//! Transactions built and signed by `tron.rs`, accepted by the TRON Nile testnet. Runs only with
//! NILE_KEY (a file with a funded Nile key in hex: some TRX and test USDT); otherwise it passes empty.

use requant_wallet::tron::{self, Tron};

fn wait(t: &Tron, txid: &str) -> tron::Outcome {
    for _ in 0..60 {
        if let Some(o) = t.outcome(txid).unwrap() {
            return o;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    panic!("{txid} did not become irreversible");
}

#[test]
fn transfers_and_a_contract_call_on_nile() {
    let Ok(path) = std::env::var("NILE_KEY") else { return };
    let key: [u8; 32] =
        requant_node::rpc::unhex(std::fs::read_to_string(path).unwrap().trim()).unwrap().try_into().unwrap();
    let d = tron::deployment("nile").unwrap();
    let t = Tron::new(d.api);
    let me = tron::address_of(&key).unwrap();
    let usdt = tron::parse(d.usdt).unwrap();
    let sink = tron::parse("TCNkawTmcQgYSU8nP8cHswT1QPjharxJr7").unwrap();
    let trx = t.trx_balance(&me).unwrap();
    let tokens = t.token_balance(&usdt, &me).unwrap();
    eprintln!("{}: {} TRX, {} USDT", tron::to_base58(&me), trx as f64 / 1e6, tron::format_units(tokens));
    assert!(trx > 20_000_000 && tokens >= 1, "fund the key with TRX and test USDT");

    let txid = t.send_trx(&key, &sink, 1).unwrap();
    let o = wait(&t, &txid);
    assert!(o.ok, "TRX transfer {txid}");

    let before = t.token_balance(&usdt, &sink).unwrap();
    let (txid, _) = t.send_call(&key, &usdt, &tron::transfer_call(&sink, 1), 30_000_000).unwrap();
    let o = wait(&t, &txid);
    assert!(o.ok, "USDT transfer {txid}");
    eprintln!("USDT transfer: energy {}, fee {} sun", o.energy, o.fee_sun);
    assert_eq!(t.token_balance(&usdt, &sink).unwrap(), before + 1);

    // a refused call reports the contract's reason
    let htlc = tron::parse(d.htlc).unwrap();
    let bogus = tron::Terms { token: usdt, sender: me, receiver: sink, amount: 1, hash: [0; 32], timeout: 1 };
    let e = t.call(&me, &htlc, &bogus.refund_call(), false).unwrap_err();
    assert!(e.contains("state"), "{e}");
    assert_eq!(t.lock_state(&htlc, &bogus, true).unwrap(), tron::LockState::None);
}
