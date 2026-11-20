/**
 * @vero/guard-sdk
 * EIP-1193 provider wrapper that routes every transaction and signature through the Vero firewall.
 * Covers Features #17 (approval capping), #18 (permit decoding), #19 (revoke) and #45 (provider wrapper).
 *
 * Fail-closed by design: if the firewall cannot be reached, times out or answers with anything other
 * than a well-formed ALLOW, the request is rejected. Opt out only with `failOpen: true`.
 */

export interface RequestArguments {
  readonly method: string;
  readonly params?: readonly unknown[] | object;
}

export interface EIP1193Provider {
  request(args: RequestArguments): Promise<unknown>;
  on?(eventName: string, listener: (...args: unknown[]) => void): void;
  removeListener?(eventName: string, listener: (...args: unknown[]) => void): void;
}

export interface CapInfo {
  token: string;
  spender: string;
  requestedAmount: bigint;
  cappedAmount: bigint;
}

export interface VeroGuardConfig {
  firewallUrl?: string; // default http://127.0.0.1:8000
  strictMode?: boolean; // reject WARN verdicts outright
  failOpen?: boolean; // INSECURE: forward requests when the firewall is unavailable
  timeoutMs?: number; // firewall request timeout, default 5000 ms
  allowUnverifiedMethods?: boolean; // INSECURE: allow eth_sign / raw tx / wallet_sendCalls unchecked
  allowUnlimitedPermits?: boolean; // INSECURE: allow signing unlimited permits
  autoCapUnlimitedApprovals?: boolean; // Feature #17
  defaultSpendCap?: bigint; // cap used when spendCapForToken is not given
  spendCapForToken?: (token: string) => bigint; // per-token cap in the token's smallest unit
  onCapped?: (info: CapInfo) => Promise<boolean>; // return false to abort instead of sending the capped tx
  onWarning?: (warnings: string[], checksum: string) => Promise<boolean>; // return true to proceed
  onBlocked?: (flags: string[], warnings: string[]) => void;
}

export interface SimulationResult {
  decision: "ALLOW" | "WARN" | "BLOCK";
  risk_score: number;
  flags: string[];
  four_word_checksum: string;
  deterministic_human_warnings: string[];
}

export const SIG_APPROVE = "095ea7b3";
export const MAX_UINT256_HEX = "f".repeat(64);
export const UNLIMITED_THRESHOLD = 2n ** 128n; // same threshold the Vero engine uses
export const DEFAULT_TIMEOUT_MS = 5000;
export const DEFAULT_SPEND_CAP = 1000n * 10n ** 18n;

const SEND_METHODS = new Set(["eth_sendTransaction", "eth_signTransaction"]);
const TYPED_DATA_METHODS = new Set(["eth_signTypedData", "eth_signTypedData_v1", "eth_signTypedData_v3",
  "eth_signTypedData_v4"]);
// These cannot be simulated from their parameters (raw bytes, blind hashes, batched calls).
const UNVERIFIABLE_METHODS = new Set(["eth_sendRawTransaction", "eth_sign", "wallet_sendCalls"]);
const DECISIONS = new Set(["ALLOW", "WARN", "BLOCK"]);

function strip0x(hex: string): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

/** Parse a decimal or 0x-hex integer string; returns null when it is not a non-negative integer. */
export function parseAmount(value: unknown): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number") return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  if (typeof value !== "string" || !/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) return null;
  return BigInt(value);
}

export function isUnlimited(amount: bigint | null): boolean {
  return amount !== null && amount >= UNLIMITED_THRESHOLD;
}

/**
 * Feature #17: rewrite approve(spender, amount >= 2^128) to approve(spender, cap).
 * Returns the original and capped amounts so the caller can tell the user.
 */
export function capUnlimitedApproval(
  calldata: string,
  cappedAmount: bigint = DEFAULT_SPEND_CAP
): { modified: boolean; calldata: string; spender?: string; requestedAmount?: bigint; cappedAmountHex?: string } {
  const clean = strip0x(calldata);
  if (clean.length !== 136 || clean.slice(0, 8) !== SIG_APPROVE || !/^[0-9a-f]+$/.test(clean)) {
    return { modified: false, calldata };
  }
  const spenderWord = clean.slice(8, 72);
  const requestedAmount = BigInt("0x" + clean.slice(72, 136));
  if (!isUnlimited(requestedAmount)) {
    return { modified: false, calldata };
  }
  const newAmountHex = cappedAmount.toString(16).padStart(64, "0");
  return {
    modified: true,
    calldata: "0x" + SIG_APPROVE + spenderWord + newAmountHex,
    spender: "0x" + spenderWord.slice(24),
    requestedAmount,
    cappedAmountHex: newAmountHex,
  };
}

/** Feature #19: approve(spender, 0) calldata to revoke an allowance. */
export function buildRevokeCalldata(spenderAddress: string): string {
  const cleanSpender = strip0x(spenderAddress);
  if (!/^[0-9a-f]{40}$/.test(cleanSpender)) {
    throw new Error(`Invalid spender address: ${spenderAddress}`);
  }
  return `0x${SIG_APPROVE}${cleanSpender.padStart(64, "0")}${"0".repeat(64)}`;
}

export interface DecodedPermit {
  type: "EIP2612" | "PERMIT2_SINGLE" | "PERMIT2_BATCH";
  token?: string;
  owner?: string;
  spender: string;
  amount: string; // decimal string
  deadline: number;
  nonce?: number;
}

function parseTypedData(typedData: unknown): any {
  if (typeof typedData !== "string") return typedData;
  try {
    return JSON.parse(typedData);
  } catch {
    throw new VeroSecurityError("Typed data is not valid JSON; refusing to sign it blind.", "BLOCK",
      ["UNPARSABLE_TYPED_DATA"], ["The signature request could not be decoded."]);
  }
}

function toDecimal(value: unknown): string {
  const parsed = parseAmount(value ?? "0");
  return parsed === null ? "0" : parsed.toString();
}

/**
 * Feature #18: decode EIP-2612 and Permit2 typed data. Returns one entry per token
 * (PermitBatch yields several), so no batched allowance can hide behind the first one.
 */
export function decodePermits(typedData: unknown): DecodedPermit[] {
  if (!typedData) return [];
  const data = parseTypedData(typedData);
  const message = data?.message || {};
  if (data?.primaryType === "Permit") {
    return [{ type: "EIP2612", token: data.domain?.verifyingContract, owner: message.owner,
      spender: message.spender, amount: toDecimal(message.value), deadline: Number(message.deadline || 0),
      nonce: Number(message.nonce || 0) }];
  }
  if (data?.primaryType === "PermitSingle" || data?.primaryType === "PermitBatch") {
    const rows = data.primaryType === "PermitSingle" ? [message.details || {}]
      : (Array.isArray(message.details) ? message.details : []);
    const type = data.primaryType === "PermitSingle" ? "PERMIT2_SINGLE" : "PERMIT2_BATCH";
    return rows.map((d: any) => ({ type, token: d.token, spender: message.spender, amount: toDecimal(d.amount),
      deadline: Number(message.sigDeadline || d.expiration || 0), nonce: Number(d.nonce || 0) }));
  }
  return [];
}

/** Backwards-compatible single-result decoder (first permit only). Prefer decodePermits. */
export function decodePermitTypedData(typedData: unknown): DecodedPermit | null {
  return decodePermits(typedData)[0] ?? null;
}

export class VeroSecurityError extends Error {
  public readonly decision: string;
  public readonly flags: string[];
  public readonly warnings: string[];

  constructor(message: string, decision: string, flags: string[] = [], warnings: string[] = []) {
    super(message);
    this.name = "VeroSecurityError";
    this.decision = decision;
    this.flags = flags;
    this.warnings = warnings;
  }
}

function block(message: string, flag: string, warning: string): VeroSecurityError {
  return new VeroSecurityError(message, "BLOCK", [flag], [warning]);
}

function validateResult(body: any): SimulationResult {
  const valid = body && DECISIONS.has(body.decision) && Array.isArray(body.flags)
    && Array.isArray(body.deterministic_human_warnings) && typeof body.four_word_checksum === "string";
  if (!valid) {
    throw block("Vero firewall returned a malformed verdict; refusing to forward.", "INVALID_FIREWALL_RESPONSE",
      "The firewall response could not be validated.");
  }
  return body as SimulationResult;
}

/** Feature #45: EIP-1193 wrapper. */
export class VeroGuardProvider implements EIP1193Provider {
  private readonly provider: EIP1193Provider;
  private readonly config: Required<Omit<VeroGuardConfig, "spendCapForToken">> & Pick<VeroGuardConfig, "spendCapForToken">;

  constructor(provider: EIP1193Provider, config: VeroGuardConfig = {}) {
    this.provider = provider;
    this.config = {
      firewallUrl: config.firewallUrl || "http://127.0.0.1:8000",
      strictMode: config.strictMode ?? false,
      failOpen: config.failOpen ?? false,
      timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      allowUnverifiedMethods: config.allowUnverifiedMethods ?? false,
      allowUnlimitedPermits: config.allowUnlimitedPermits ?? false,
      autoCapUnlimitedApprovals: config.autoCapUnlimitedApprovals ?? true,
      defaultSpendCap: config.defaultSpendCap ?? DEFAULT_SPEND_CAP,
      spendCapForToken: config.spendCapForToken,
      onCapped: config.onCapped || (async () => true),
      onWarning: config.onWarning || (async () => false), // WARN needs an explicit yes
      onBlocked: config.onBlocked || (() => {}),
    };
  }

  async request(args: RequestArguments): Promise<unknown> {
    const { method, params } = args;
    if (SEND_METHODS.has(method)) {
      const first = Array.isArray(params) ? params[0] : params;
      if (!first || typeof first !== "object") {
        throw block(`${method} called without a transaction object`, "MALFORMED_TRANSACTION", "No transaction to check.");
      }
      const txParams: Record<string, any> = { ...(first as object) };
      await this.applyApprovalCap(txParams);
      await this.interceptAndVerifyTransaction(txParams);
      return this.provider.request({ method, params: [txParams] });
    }
    if (TYPED_DATA_METHODS.has(method)) {
      this.checkTypedData(params);
    }
    if (UNVERIFIABLE_METHODS.has(method) && !this.config.allowUnverifiedMethods) {
      throw block(`[VERO GUARD] ${method} cannot be simulated and is blocked.`, "UNVERIFIABLE_METHOD",
        "This request type cannot be explained before signing.");
    }
    return this.provider.request(args);
  }

  private async applyApprovalCap(txParams: Record<string, any>): Promise<void> {
    const data = txParams.data ?? txParams.input;
    if (!this.config.autoCapUnlimitedApprovals || typeof data !== "string") return;
    const token = String(txParams.to || "");
    const cap = this.config.spendCapForToken ? this.config.spendCapForToken(token) : this.config.defaultSpendCap;
    const result = capUnlimitedApproval(data, cap);
    if (!result.modified) return;
    const proceed = await this.config.onCapped({ token, spender: result.spender!, requestedAmount: result.requestedAmount!,
      cappedAmount: cap });
    if (!proceed) {
      throw block("User declined the capped approval.", "APPROVAL_CAP_DECLINED", "Unlimited approval was not sent.");
    }
    txParams.data = result.calldata;
    delete txParams.input; // one source of truth for the calldata that gets signed
  }

  private checkTypedData(params: unknown): void {
    const raw = Array.isArray(params) ? params.find((p) => typeof p === "object" || (typeof p === "string" && p.trim().startsWith("{"))) : params;
    const permits = decodePermits(raw);
    const unlimited = permits.find((p) => isUnlimited(parseAmount(p.amount)));
    if (unlimited && !this.config.allowUnlimitedPermits) {
      throw block(`[VERO GUARD] Gasless permit grants UNLIMITED allowance to spender ${unlimited.spender}.`,
        "UNLIMITED_GASLESS_PERMIT", "Spender could drain this token without paying gas.");
    }
  }

  private async buildPayload(tx: Record<string, any>) {
    const value = parseAmount(tx.value ?? "0");
    if (value === null) {
      throw block(`Malformed transaction value: ${String(tx.value)}`, "MALFORMED_TRANSACTION", "Value is not an integer.");
    }
    const chainId = parseAmount(tx.chainId ?? (await this.provider.request({ method: "eth_chainId" })));
    if (chainId === null) {
      throw block("Could not determine the chain id.", "MALFORMED_TRANSACTION", "Chain id is unknown.");
    }
    return {
      chain_id: Number(chainId),
      safe_address: tx.from || "0x0000000000000000000000000000000000000000",
      to: tx.to || "0x0000000000000000000000000000000000000000",
      value: value.toString(),
      data: tx.data ?? tx.input ?? "0x",
      nonce: tx.nonce !== undefined ? Number(parseAmount(tx.nonce) ?? 0n) : 0,
    };
  }

  private async fetchVerdict(payload: object): Promise<SimulationResult | null> {
    try {
      const response = await fetch(`${this.config.firewallUrl}/v1/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
      if (!response.ok) throw new Error(`Firewall returned HTTP ${response.status}`);
      return validateResult(await response.json());
    } catch (err: any) {
      if (err instanceof VeroSecurityError) throw err;
      if (this.config.failOpen) return null; // explicit, insecure opt-in
      throw block(`Vero firewall unavailable: ${err?.message ?? err}`, "FIREWALL_UNAVAILABLE",
        "Transaction safety could not be verified, so it was not sent.");
    }
  }

  private async interceptAndVerifyTransaction(tx: Record<string, any>): Promise<void> {
    const result = await this.fetchVerdict(await this.buildPayload(tx));
    if (result === null || result.decision === "ALLOW") return;
    const warnings = result.deterministic_human_warnings;
    if (result.decision === "BLOCK") {
      this.config.onBlocked(result.flags, warnings);
      throw new VeroSecurityError(`[VERO BLOCKED] Dangerous transaction rejected: ${warnings.join(" ")}`,
        result.decision, result.flags, warnings);
    }
    if (this.config.strictMode || !(await this.config.onWarning(warnings, result.four_word_checksum))) {
      throw new VeroSecurityError(`Transaction not confirmed after warnings [Checksum: ${result.four_word_checksum}]`,
        result.decision, result.flags, warnings);
    }
  }
}

export function createVeroGuard(provider: EIP1193Provider, config?: VeroGuardConfig): VeroGuardProvider {
  return new VeroGuardProvider(provider, config);
}
