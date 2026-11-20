# Vero simulator: EVM simulation and risk engine (Person 2)

Python 3.11+ package that explains and scores a Safe multisig transaction before anyone signs it.
It decodes the exact bytes, optionally simulates them on a local Anvil fork, builds a state diff,
compares it with what the signer declared, runs deterministic rules and renders plain English.
No AI is involved anywhere in the verdict path.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Use from the API (Person 3)

```python
from shared.api_schemas import SimulationRequest
from simulator.context import EngineContext
from simulator.engine import simulate, analyze_offline
from simulator.tracer.anvil_fork_simulator import AnvilForkSimulator

sim = AnvilForkSimulator("http://127.0.0.1:8545")      # one instance per Anvil; it serialises calls
result = await simulate(request, EngineContext(), sim)  # fork mode
result = analyze_offline(request, EngineContext())      # static mode, no node needed
```

Both return `SimulationResult` (see `shared/api_schemas.py`). `result.mode` says which path ran.
`EngineContext` carries the threat registry, contacts, recipient history, balances and token
metadata; `EngineContext.from_mapping(dict)` builds it from JSON.

Other entry points:

| Need | Function |
|---|---|
| Decode `eth_signTypedData_v4` permit (EIP-2612, Permit2) | `decoders.permit_and_bridge_decoders.decode_permit_typed_data`, `describe_permit` |
| Calldata digest for both devices | `decoders.erc7730_and_8213.calldata_digest` |
| ERC-7730 clear-signing fields | `load_descriptor`, `format_with_descriptor` |
| Proxy slot / codehash read (#06) | `AnvilForkSimulator.inspect_proxy` |

## Benchmark

```bash
.venv/bin/python -m simulator.bench.build_scenarios   # regenerate the 55 scenario files
.venv/bin/python -m simulator.bench.run_eval           # static mode
.venv/bin/python -m simulator.bench.run_eval --rpc http://127.0.0.1:8545   # fork mode
```

Writes `simulator/bench/results/benchmark.{json,md}`.

## Tests

```bash
.venv/bin/python -m pytest --cov
```

Live Anvil tests need Foundry (installed to `~/.foundry/bin`) and compiled fixtures; they skip otherwise:

```bash
export PATH="$PATH:$HOME/.foundry/bin"
cd tests/integration/contracts && forge build && cd -
.venv/bin/python -m pytest tests/integration -s
```

## Rule ids

R1 approvals, R2 permits, R3 implementation/code swap, R4 unknown delegatecall, R5 owners/threshold
and ownership transfer, R6 guard, R7 modules, R8 EIP-7702, R9 undeclared recipient or asset,
R10 outflow above cap, R11 lookalike token, R12 threat registry. Shields: `B26-*` behavioural,
`G28-*` gas ceiling, `C31-CHAIN` chain binding, `P33-POISON` address poisoning, `B36-BRIDGE`
unknown bridge destination, `DECODE` undecodable batch. HIGH and CRITICAL count as blocking.

## Schema changes from the pasted contract (all additive, defaults keep old clients working)

- `TransactionTuple.authorizationList` (EIP-7702), `SimulationRequest.userOperation` (#28) and `label` (what the UI claimed).
- `IntentPolicy.maxGasFeeWei`. `maxOutflowWei` is applied **per asset** in that asset's smallest unit, because summing ETH wei with 6-decimal USDT is meaningless.
- `StateDiffSummary.guardChanges` and `bridgeTransfers`; `OwnerChange.newThreshold` is now optional (null when unchanged) and `oldThreshold` was added.
- `SimulationResult.mode`, `calldataDigests`, `revertReason`; `BenchmarkMetrics.p50LatencyMs`, `mode`, extra intervals.
- All models are frozen and validate addresses (lowercased), hex and unsigned-integer strings.

## Known limits

- Live tests (`tests/integration/`) run on a plain local Anvil with fixture contracts. They have not been run on a
  mainnet fork (`anvil --fork-url <RPC>`), which needs an RPC provider URL.
- Fork-mode benchmark on a plain Anvil: the mainnet token contracts do not exist there, so token effects come from
  the calldata gap-fill, not from executed logs. The harness funds each Safe with its declared ETH via
  `anvil_setBalance`, so point it only at a disposable node.
- Benchmark scores are 100 % because the same person wrote rules and scenarios. The held-out set needs an outside author.
- `full-vero` block rate is modelled, not measured on-chain.
- The "ERC-8213" digest number is unverified (blueprint ADR-12); call it a calldata digest on slides.
- Bridge chain tables cover common mainnet deployments only; unknown destinations raise `B36-BRIDGE`.
- Open review items: CCIP reports only the first token of a multi-token `ccipSend`; `setModuleGuard` and
  `execTransactionFromModule` are not decoded; canonical token list is chain 1 only; the contract-age check
  fails open (logged) when the node cannot serve the 24-hour-old block.
- Fail-closed behaviour: known selectors with non-strict ABI arguments raise `DECODE` (CRITICAL); a reverted
  fork simulation raises `SIM-REVERTED` (HIGH) and falls back to calldata-predicted effects.

## Firewall API integration (api-agents)

`api-agents/api_agents/adapters/vero_engine_adapter.py` puts this engine behind the firewall API's
`SimulatorProtocol` / `RuleEngineProtocol`. The REST routes and the MCP server both use it by default.

| Env var | Effect |
|---|---|
| `VERO_ENGINE=real` (default) | Vero engine, static calldata analysis |
| `VERO_ENGINE=mock` | Original `MockAdapter` (starts without the engine installed) |
| `VERO_ANVIL_RPC=http://127.0.0.1:8545` | Fork simulation; if the node is unreachable the verdict falls back to static and carries `FORK_UNAVAILABLE` |

`SimulateRequest` gained optional `operation` (0 CALL, 1 DELEGATECALL), `declared_intent`
(`allowed_recipients`, `allowed_tokens`, `max_outflow_wei`) and `label`. Decision mapping: any HIGH/CRITICAL
alert is BLOCK, MEDIUM is WARN, otherwise ALLOW. Flags use names such as `INFINITE_TOKEN_APPROVAL`,
`MODULE_ENABLED`, `UNDECLARED_RECIPIENT`; warnings are prefixed with the rule id.
