// Progress from the first on-device run (pasted from "Copy report"), so it
// survives the harness rebuild. Loaded only when nothing is saved yet.
export const SEED_REPORT = `### PQ1 device test — 2026-10-19

Device . 6/9 scenarios OK (30 not run).

| Group | Scenario | Expected | Result | Screen check |
| --- | --- | --- | --- | --- |
| Sends | Send ETH to an address with no name | Send 0.01 ETH to 0x1234…5678 (raw address), Ethereum, fee shown | signed: Signed (4128 B signature). Nothing was sent. | matches |
| Sends | Send USDC | Send 25 USDC to 0x1234…5678 (token symbol and decimals from the catalog) | signed: Signed (4128 B signature). Nothing was sent. | matches |
| Sends | Send a token that is not in the catalog | Unknown-token warning page: raw token address and raw amount, not a symbol | signed: Signed (4128 B signature). Nothing was sent. | matches |
| Sends | Send USDC on Base | Send 10 USDC to 0x1234…5678, network shown as Base | signed: Signed (4128 B signature). Nothing was sent. | matches |
| Sends | Send ETH on Base Sepolia | Send 0.001 ETH to 0x1234…5678, network shown as Base Sepolia (testnet) | signed: Signed (4128 B signature). Nothing was sent. | matches |
| Approvals | Approve 100 USDC for Permit2 | Approve 100 USDC, spender shown by name (Permit2) | signed: Signed (4128 B signature). Nothing was sent. | wrong |
| Approvals | Unlimited USDT approval for Uniswap V2 | Approve UNLIMITED USDT (clearly marked as unlimited), spender shown by name (Uniswap V2 router) | FAILED: Something went wrong while talking to the PQ1. Unplug it, plug it back in, and try again. (device: SIGN_USEROP failed: SW=0x6f00 [no code]) | wrong |
| Approvals | Revoke DAI approval (approve 0) | Approve 0 DAI (revoke), spender shown by name (CoW Vault Relayer) | signed: Signed (4128 B signature). Nothing was sent. | matches |
| Contract calls | Wrap ETH into WETH | Clear-signed contract call. Same facts as the ERC-7730 registry reference (weth/tests/calldata-weth.tests.json): Interaction with · WETH · Amount · 0.00187 ETH · Max fees · 0.00007322104817819 1 ETH | FAILED: Something went wrong while talking to the PQ1. Unplug it, plug it back in, and try again. (device: SIGN_USEROP failed: SW=0x6f00 [no code]) | wrong |
`
