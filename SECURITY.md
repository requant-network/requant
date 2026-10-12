# Security policy

## Status

Pre-alpha. A public test network is running; its coins have no value and it may be reset. An internal security review is planned for the work function,
the chain rules, the node, the wallet, the swap maker and the RequantHtlc contract.
That review has not yet been completed. Do not use it where real funds depend on it.

## In scope

- A divergence between `SPEC.md`, the Rust crate, the Python reference or the CUDA code (any input
  on which two of them disagree is a consensus bug).
- A **work-model break**: a way to obtain valid tickets for less than the stated `L n w`
  multiply-adds each, or to pass verification without the recomputed piece.
- Crashes, panics or unbounded resource use in the verifier, the node or the pool on malformed blocks,
  transactions, messages or RPC requests; a way to stall synchronisation or split the network.
- **Wallet**: signing something other than intended, leaking a recovery phrase, key, passphrase or swap
  secret, or accepting a forged parent transaction, condition or channel state.
- **Swaps and channels**: a way for the maker, the taker or a third party to take both sides of a swap,
  to keep a payment without delivering, or to close a channel on an old state (`SWAPS.md`,
  `contracts/`).
- **Releases**: a way to make a node install an update that the release key did not sign.

## How to report

Open a private security advisory on this repository (`Security` -> `Report a vulnerability`), or email
dev@requant.network with **[Security]** in the subject. For non-sensitive findings a regular issue is
fine. Include the affected version or commit, a minimal reproduction and the expected versus observed
result. Never send a real recovery phrase or private key.

On the test network, work-model breaks are published as results rather than embargoed; node, wallet and
swap vulnerabilities are fixed in a release before they are disclosed.
