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

Status: tested locally only; not yet deployed or reviewed. No real value before an external review.
