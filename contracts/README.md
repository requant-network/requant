# Contracts

`src/RequantHtlc.sol` is the token side of an HTLC swap with Requant ([SWAPS.md](../SWAPS.md)): one
contract holds any number of locks of TRC-20 or ERC-20 tokens, each paid to its receiver against the
32-byte SHA-256 preimage of its hash before its timeout (unix seconds), or returned to its sender from
the timeout on. The hash is the same plain SHA-256 as the Requant and Bitcoin HTLCs, so one secret
serves both chains.

- A lock's id is the hash of all its terms, including the sender, so nobody can occupy an id another
  sender wants.
- Anyone may submit the secret or the refund; the tokens only go to the receiver or back to the sender.
- Transfers are checked by the contract's balance, not the token's return value (USDT does not report
  reliably), and fee-on-transfer tokens are refused.
- The bytecode targets Istanbul (`foundry.toml`), which TRON's TVM follows.

Tests use [Foundry](https://github.com/foundry-rs/foundry) and no libraries:

```sh
forge test --root contracts
```

`scripts/check.py` runs `forge fmt --check` and `forge test` when `forge` is on the PATH or `FORGE`
names it.

## On the TRON Nile testnet

Deployed at `TBBkQ4hqoH9Ji21QQ5mb6t22MxjWknFiwk` (tx `37d75c7b…a614`) with test USDT
`TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf`. Checked there on 2026-10-11: `block.timestamp` is in seconds;
lock, claim by secret and refund after the timeout work; a past timeout, a wrong secret, changed terms,
an early refund and a late claim are refused. Energy per call (the caller pays all of it):

| Call | Energy | Burned at Nile prices |
|---|---|---|
| USDT `approve` (once) | 22,688 | 0.3 TRX (the Nile USDT contract pays part of its energy) |
| `lock` | 43,638 (58,638 for a first lock) | 4.8 TRX |
| `claim` | 27,403 | 3.2 TRX |
| `refund` | 26,500 | 3.1 TRX |
| deployment | 574,801 | 61.5 TRX |

An earlier version that stored every term took 189,603 energy per lock and 52,132 per claim.

Status: tested locally and on Nile; not reviewed. No real value before an external review.
