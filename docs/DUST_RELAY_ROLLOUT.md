# Gated dust relay policy

This change prepares `--reject-dust-outputs`. The default remains **off** until every supported sending wallet and pool payout builder has been released with the small-change fix. It is not enabled by this PR and must not be added to production service arguments before that rollout is verified.

With the flag enabled, standalone mempool admission and every member of package admission reject transfer outputs below 1000 atoms. The threshold includes intended small recipient outputs as well as change. Package admission remains atomic. Restored/reorganized pool entries go through the same policy or are removed during revalidation. `getmempoolinfo` reports `reject_dust_outputs` and `dust_threshold` so operators can verify the actual setting.

This is relay/mining policy, not consensus. A valid block containing a smaller output remains accepted. Existing small inputs remain spendable when consolidated into outputs at or above the threshold. No activation height, chain fork, transaction format or minimum-fee consensus change is introduced.

## Rollout gate

1. Release the upstream CLI/pool wallet and the downstream native, Android, web and extension wallets with the patched planners. Confirm all supported callers include discarded change in their reviewed fee. Preserve recovery for existing wallet files.
2. Validate funded testnet/regtest payments with 0, 1, 999, 1000 and 1001 atoms of change. Confirm the recipient amount remains exact and reviewed fee equals actual input-minus-output fee. Test both CLI/offline and GUI signing paths.
3. Confirm package relay, old dust consolidation and valid dust-containing block acceptance. Do not infer wallet readiness from a peer's user-agent string.
4. Once the releases are deployed and confirmed, explicitly add `--reject-dust-outputs` to selected node service arguments in a separate reviewed operational change. Check `getmempoolinfo` and relay failures. Expanding to other nodes remains an operator decision.
5. To roll back relay policy, remove the flag and restart the node. Consensus and confirmed history are unchanged; the pool may need transactions resubmitted.

The source wallet already had the modern payment-plan change threshold, but its legacy `build_transfer` still produced small change. This PR fixes that path too and adds the missing import-cost bounds (131072 KiB memory, six passes, four lanes) before Argon2 allocation. Tests cover both planners and boundary values. The related `requant-wallet`/extension changes must be released before enabling the node flag.
