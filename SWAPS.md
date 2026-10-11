# Swaps and payment channels

Status: **consensus primitives, pool policy, package relay, wallet commands, one-way payment
channels, and buying RQT from a maker with BTC (on chain or over Lightning) or with USDT on TRON; no
other chains, Monero or two-way channel software yet.** Since
node 0.15.0 the chain has 2-of-2 conditions, hash/time-locked contracts (HTLCs) and absolute and
relative time locks ([CHAIN.md §4.1](CHAIN.md)); since node 0.16.0 also revocable outputs, revocable
HTLCs and anyone-can-pay signatures ([§4.2](CHAIN.md)), and a pool that ranks packages (child pays for
parent) and replaces by fee ([§4.3](CHAIN.md)). On the test network they are active from heights 1400
and 4700, on the main network from genesis. `requant-wallet` describes conditions, locks coins under
them and spends them along each path (`condition`, `spend-condition`, `cosign`), and runs one-way
payment channels (`channel`, wallet 0.7.0) and swaps with a maker (`swap`, `requant-maker`). The other
protocols below are built in software on top of the same primitives and **do not exist yet**: swaps
with other chains and Monero, and two-way channels. The point of having the primitives now is that
adding them later needs no hard fork.

## The primitives

| Primitive | In consensus as |
|---|---|
| Hash lock | HTLC claim path: the 32-byte SHA-256 preimage and the claim key |
| Time lock | HTLC refund path (absolute height); `after_height` and `after_blocks` on any input |
| 2-of-2 | Multi2 condition: two ed25519 keys sign the same transaction |
| Revocable output | `delayed`: the owner after a relative delay, the revocation key at any time |
| Revocable HTLC | as an HTLC, with delays on claim and refund and a revocation path |
| Anyone-can-pay | a signature over its own input and all outputs, so others may add inputs |
| k-of-n | off chain: FROST or MuSig2 aggregate ed25519 keys into one ordinary key |

A locked coin pays a hash like any address, so locking is an ordinary transfer. The spending input
reveals the condition. Txids exclude signatures, so a transfer can be signed by both parties before
its parent is even confirmed, and its reference stays valid. Every protocol below depends on this.

## 1. HTLC swaps (Bitcoin family, EVM)

Party A picks a secret `s` and publishes `H = SHA256(s)`.

1. A locks RQT in an HTLC: hash `H`, claim key B, refund key A, timeout `t_RQT`.
2. B locks the other coin under the same `H`, refundable to B at an earlier timeout `t_other`.
   On Bitcoin, Litecoin, Bitcoin Cash and Dogecoin this is the standard `OP_SHA256` +
   `OP_CHECKLOCKTIMEVERIFY` script; on EVM chains it is a contract.
3. A claims the other coin, which reveals `s` on that chain.
4. B claims the RQT with `s`.

If either side stops, both refund after their timeouts. The RQT timeout must be the later one
(`t_RQT` well after `t_other`), so that B always has time to use `s` once A reveals it.

### Implemented: buying RQT with BTC from a maker (wallet 0.8.0)

The party with the secret pays first and has the longer time lock, so here the taker (who has BTC and
wants RQT) goes first:

1. `requant-wallet swap buy MAKER AMOUNT WALLET --out SWAP.json`: the taker picks the secret and a
   Bitcoin refund key; the maker answers with a P2WSH HTLC (claim: the maker's key with the secret;
   refund: the taker's key after 144 Bitcoin blocks, about a day) and its price. The wallet checks the
   address against the parameters before showing it. The taker pays it from any Bitcoin wallet.
2. Once the payment has its confirmations (1 up to 0.01 BTC, 3 up to 0.1, 6 above), `requant-maker`
   locks the RQT in a Requant HTLC with the same hash: claim by the taker, refund to the maker after 360
   Requant blocks (about six hours). It does so only while at least 72 Bitcoin blocks (about twelve
   hours) are left to the taker's refund, so a claim at the last Requant moment still leaves it time.
3. `swap claim SWAP.json WALLET` takes the RQT and reveals the secret on Requant; the maker reads it
   there and claims the BTC.

If the maker never locks (unpaid within 12 blocks, underpaid, paid too late), the taker takes the BTC
back with `swap refund SWAP.json BTC_ADDRESS` from the Bitcoin timeout; if the taker never claims, the
maker takes the RQT back at the Requant timeout. The Bitcoin script requires a 32-byte secret
(`OP_SIZE 32`), as Requant does, so a secret of another length cannot open one side only.

`requant-maker run CONFIG.json` serves takers over JSON-RPC (`info`, `swap_create`, `swap_status`) and
needs a Bitcoin Core node and a Requant node API. `tests/test_swap_e2e.py` runs both chains on regtest
(a completed swap, an underpaid and a late one refunded to the taker, one the taker never claims) with
`BITCOIND=/path/to/bitcoind`.

### Implemented: paying over Lightning (wallet 0.9.0)

Lightning payments are locked by the SHA-256 of a 32-byte preimage, as Requant HTLCs are, so the same
secret ties both sides and nothing waits for Bitcoin confirmations:

1. `requant-wallet swap buy-ln MAKER AMOUNT WALLET --out SWAP.json`: the maker's LND makes a *hold
   invoice* locked by the taker's hash (it cannot take the payment: it does not know the secret). The
   wallet decodes the invoice and refuses it unless its payment hash is the taker's own, its network
   the maker's and its amount the price. The taker pays it from any Lightning wallet.
2. Once LND holds the payment, `requant-maker` locks the RQT for 60 Requant blocks (about an hour), but
   only while the held payment has at least 18 Bitcoin blocks (about three hours) left.
3. `swap claim` takes the RQT and reveals the secret; the maker settles the invoice with it.

A payment the maker does not complete (underpaid, too little time left, the RQT could not be locked,
or the taker never claimed and the maker took the RQT back) is cancelled, and it goes back to the
taker's Lightning wallet by itself: no refund to wait for. The maker needs LND with `--no-rest-tls` on
its own host and a macaroon that can add, settle and cancel invoices. `tests/test_swap_ln_e2e.py`
runs it on regtest with two LND nodes (BITCOIND=... LND=...): a completed swap, a lock the maker
cannot make, and an unclaimed swap.

### Implemented: paying with USDT on TRON (wallet 0.10.0)

The token side is the RequantHtlc contract ([contracts/](contracts/README.md)): a lock pays its receiver
against the 32-byte SHA-256 preimage of its hash before its timeout (unix seconds), and goes back to its
sender from then on. Locks are identified by a hash of all their terms, and only their state is stored
(about 44,000 energy per lock on TRON). The wallet accepts only the deployments it knows
(`tron::DEPLOYMENTS`; on the Nile testnet so far), so a maker cannot point a taker at a contract of its
own.

1. `requant-wallet swap buy-usdt MAKER AMOUNT WALLET --out SWAP.json`: the taker picks the secret and a
   new TRON key for this swap; the maker answers with the lock's terms (its USDT, the maker as receiver,
   the taker's hash, the price, a refund twelve hours on). The wallet checks every term. The taker sends
   the USDT and some TRX for the fees to the swap's own TRON address, from any wallet or exchange.
2. `swap lock SWAP.json` approves the contract (once) and locks the USDT from that address.
3. Once the lock is irreversible (about a minute: TRON's solidified blocks) and was made within two
   hours of the offer, `requant-maker` locks the RQT for 120 Requant blocks (about two hours), and only
   while four hours are left to the taker's refund.
4. `swap claim` takes the RQT and reveals the secret; the maker claims the USDT with it.

If the maker never locks, the taker takes the USDT back with `swap refund SWAP.json` from the timeout,
and `swap withdraw SWAP.json TRON_ADDRESS` moves it out of the swap's address. The wallet builds and
signs TRON transactions itself (`tron.rs`); the TRON API (TronGrid by default, `--tron-api` for another)
only reads the chain and relays them. On Nile (2026-10-11) a swap of 1 RQT took the lock (43,638
energy), the RQT lock, the claim of the RQT and the maker's claim of the USDT (27,403 energy) in about
four minutes. Configure the maker with `"tron": {"network", "key", "units_per_rqt"}`; its TRON address
needs TRX (or energy) for its claims.

The taker needs no TRX: when the swap's address holds the USDT but cannot pay for the approval and
the lock, `swap lock` asks the maker (`swap_fees`). The maker lends energy from its stake when it has
enough to lend (`requant-maker tron-stake`; it takes the energy back once the lock is made, or after an
hour), else it sends the TRX the address would burn, and `swap claim` returns what was not burned. It
does so once per swap, only for an address that already holds the USDT, and for ten swaps at a time.
Lending is the cheap way at scale, but the stake is large: about 1,360 staked TRX for the 100,000 energy
reserved for one lock on Nile (the energy per staked TRX depends on the network's totals); with less,
the maker pays in TRX (about 5 TRX burned per lock on Nile, on top of its own claim). On Nile, a swap paid
with USDT only worked end to end that way, and lending 10 staked TRX (736 energy) and taking it back
worked; a whole swap on lent energy waits for a larger stake.

**Privacy: weak, and it should be said so.** The same `H` appears on both chains, and the amounts and
timing match. Anyone watching both chains can link the two halves. The HTLC is also visible on RQT
when it is spent: its claim or refund path is revealed.

## 2. Swaps with Monero (adaptor signatures)

Monero has no scripts and no hash locks. A swap with it uses adaptor signatures plus time locks on
the other chain, which RQT now has. The usual design (as in the Bitcoin–Monero swaps):

1. **Lock.** The RQT side locks coins under 2-of-2 (A, B). Before broadcasting, both sign:
   - a *cancel* transfer of the lock coin to a new 2-of-2, valid `after_blocks = t1` after the lock;
   - a *refund* transfer from the cancel output back to the RQT seller;
   - a *punish* transfer from the cancel output to the buyer, valid `after_blocks = t2` after the
     cancel.
2. **Monero side.** The XMR is sent to an address whose spend key is shared between the parties.
3. **Redeem.** Redeeming the RQT completes an adaptor signature. The completed signature reveals the
   secret half of the Monero key, so the other party can sweep the XMR.
4. **Refund or punish.** If a party stops, the cancel, refund and punish paths with their relative
   locks settle the coins without trust.

RQT and Monero use the same curve (ed25519). The adaptor secret is therefore one scalar on both
sides, and no cross-curve proof of equal discrete logarithms is needed (Bitcoin–Monero swaps need
one).

**What has to be built:**
- ed25519 adaptor signatures, which need random nonces: the deterministic nonce of plain ed25519
  does not apply;
- the swap state machine and a maker bot;
- an external cryptographic review before real money.

**Privacy.**
- If the 2-of-2 is the consensus Multi2 condition, it is visible when spent. Swaps whose RQT side
  looks like an ordinary transfer need the two keys aggregated off-chain into one (MuSig2 on
  ed25519). The result is checked by the ordinary single-key rule, so no consensus change is needed.
  Until that exists, say the swap is visible.
- The Monero side keeps Monero's privacy.
- Amounts and timing can still correlate the two halves.

## 3. Payment channels (MagnetGate)

Paying for traffic is one-way, client to server, and needs only 2-of-2 and an absolute lock:

1. The client locks a deposit under 2-of-2 (client, server).
2. The server signs a *refund* of the whole deposit to the client, valid from an expiry height.
3. For each piece of traffic, the client signs a new transfer from the deposit that pays the server
   more and itself the rest. The server keeps the last one.
4. Before the expiry, the server publishes the last state; that spends the deposit, and the refund
   can never be used. If the server disappears, the client takes the refund at the expiry.

There is no revocation and no penalty: a newer state always pays the server more, so the server never
wants to publish an older one. The consensus test `one_way_payment_channel` walks through exactly
this.

`requant-wallet channel` (0.7.0) implements it; the channel file is shared by both sides and holds no
secret:

```sh
requant-wallet channel open client.wallet SERVER_PUBKEY SERVER_ADDRESS 5 EXPIRY --out ch.json  # client
requant-wallet channel accept server.key ch.json          # server: checks it, signs the refund
requant-wallet channel fund client.wallet ch.json         # client: only now sends the deposit
requant-wallet channel pay client.wallet ch.json 0.25 --out s.hex   # client: total paid so far
requant-wallet channel receive ch.json s.hex              # server: {"paid", "funded", "blocks_left", ...}
requant-wallet channel close server.key ch.json s.hex     # server: before the expiry
requant-wallet channel refund ch.json                     # client: from the expiry, if never closed
```

- The file carries the funding transfer without signatures. The txid does not cover them, so the
  refund the server signs refers to the right deposit, but the server cannot send the deposit and hold
  the client's coins before it has signed the refund. `fund` refuses to send a deposit whose refund
  the server has not signed.
- The server should count payments only once the deposit is confirmed (`receive` says so) and must
  close well before the expiry: from the expiry the client's refund is valid too, and whichever
  confirms first wins. `accept` refuses a channel shorter than `--min-blocks` (default 144).
- The refund and every state pay a fixed fee of 1000 atoms; with package relay a child of either can
  pay more.

**Two-way channels** use the revocable templates of §4.2, as Lightning does. Each party holds its own
version of the latest commitment transfer from the 2-of-2 deposit, in which its own balance pays a
revocable output (`delayed`: itself after `delay` blocks, or the other party's revocation key at once)
and the other party's balance pays the other party directly. Moving to a new state, each side hands
over the secret of its revocation key for the old one. Publishing a revoked state then lets the other
side take the publisher's balance through the revocation path before the delay ends. Payments routed
through channels sit in revocable HTLCs (claim with the preimage, refund after the timeout, both after
a delay; revocation at once). The templates are in consensus; the channel software is large and
needs review.

## Before any of this carries real value

- **Finality.** A swap is only as safe as the depth of reorganisation it can survive. A small
  proof-of-work chain can be rewritten by an attacker with enough hashrate; the attacker could undo
  the RQT side after receiving the other coin. Swap software must wait for confirmations scaled to
  the amount and the network's hashrate, and say so to users. TNet hashrate cannot be rented on the
  usual GPU markets, which helps but does not remove this risk.
- **Fees on pre-signed transfers.** Refunds and cancels are signed long before they are sent. If fees
  rise in between, there are three ways to get them in: a child spending one of their outputs pays
  for both (packages are ranked together, and since node 0.17.0 relayed together, so the pre-signed
  parent may pay nothing); a signer who used anyone-can-pay lets anyone add an input that raises the
  fee; and a single-signer transfer can be replaced by fee. A pre-signed transfer therefore only
  needs an output its owner can spend with a child.
- **Review.** The consensus rules are small, fixed templates with tests
  (`crates/consensus/tests/conditions.rs`). The protocols need their own review, the Monero one most
  of all.
