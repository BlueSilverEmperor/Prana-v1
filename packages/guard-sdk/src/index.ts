/**
 * @vero/guard-sdk
 * Comprehensive EIP-1193 Provider Wrapper, Retail Protection Guard & Permit2 Decoder.
 * Covers Features #17, #18, #19, and #45.
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

export interface VeroGuardConfig {
  firewallUrl?: string; // Default: http://127.0.0.1:8000
  strictMode?: boolean; // If true, WARN is also rejected
  autoCapUnlimitedApprovals?: boolean; // Feature #17: Auto cap 2^256-1 approvals
  defaultSpendCap?: bigint; // Default max approval cap (e.g. 1000 * 10^18)
  onWarning?: (warnings: string[], checksum: string) => Promise<boolean>;
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

/**
 * Feature #17: Automatic Unlimited Approval Capping.
 * Rewrites approve(spender, MAX_UINT256) calldata to exact needed or capped amount.
 */
export function capUnlimitedApproval(
  calldata: string,
  cappedAmount: bigint = 1000n * 10n ** 18n
): { modified: boolean; calldata: string; cappedAmountHex?: string } {
  const clean = calldata.startsWith("0x") ? calldata.slice(2).toLowerCase() : calldata.toLowerCase();
  if (clean.length < 136 || clean.slice(0, 8) !== SIG_APPROVE) {
    return { modified: false, calldata };
  }

  const spender = clean.slice(8, 72);
  const amountHex = clean.slice(72, 136);

  // Check if amount is MAX_UINT256 or nearly 2^256-1
  if (amountHex === MAX_UINT256_HEX || amountHex.startsWith("ffffffff")) {
    const newAmountHex = cappedAmount.toString(16).padStart(64, "0");
    const rewritten = "0x" + clean.slice(0, 8) + spender + newAmountHex;
    return {
      modified: true,
      calldata: rewritten,
      cappedAmountHex: newAmountHex,
    };
  }

  return { modified: false, calldata };
}

/**
 * Feature #19: Open-Approval Scanner & One-Click Revoke.
 * Generates approve(spender, 0) calldata to revoke allowance immediately.
 */
export function buildRevokeCalldata(spenderAddress: string): string {
  const cleanSpender = spenderAddress.startsWith("0x") ? spenderAddress.slice(2).toLowerCase() : spenderAddress.toLowerCase();
  const paddedSpender = cleanSpender.padStart(64, "0");
  const zeroAmount = "0".repeat(64);
  return `0x${SIG_APPROVE}${paddedSpender}${zeroAmount}`;
}

export interface DecodedPermit {
  type: "EIP2612" | "PERMIT2_SINGLE" | "PERMIT2_BATCH";
  token?: string;
  owner?: string;
  spender: string;
  amount: string;
  deadline: number;
  nonce?: number;
}

/**
 * Feature #18: Gasless Off-Chain Permit Decoder for EIP-2612 & Permit2.
 * Parses typed data parameters for eth_signTypedData_v4 to reveal hidden spender & amounts.
 */
export function decodePermitTypedData(typedData: any): DecodedPermit | null {
  if (!typedData) return null;
  const data = typeof typedData === "string" ? JSON.parse(typedData) : typedData;
  const primaryType = data.primaryType;
  const message = data.message || {};

  // EIP-2612 Permit
  if (primaryType === "Permit") {
    return {
      type: "EIP2612",
      token: data.domain?.verifyingContract,
      owner: message.owner,
      spender: message.spender,
      amount: String(message.value || "0"),
      deadline: Number(message.deadline || 0),
      nonce: Number(message.nonce || 0),
    };
  }

  // Uniswap Permit2: PermitSingle
  if (primaryType === "PermitSingle") {
    const details = message.details || {};
    return {
      type: "PERMIT2_SINGLE",
      token: details.token,
      spender: message.spender,
      amount: String(details.amount || "0"),
      deadline: Number(message.sigDeadline || details.expiration || 0),
      nonce: Number(details.nonce || 0),
    };
  }

  // Uniswap Permit2: PermitBatch
  if (primaryType === "PermitBatch") {
    const details = Array.isArray(message.details) && message.details.length > 0 ? message.details[0] : {};
    return {
      type: "PERMIT2_BATCH",
      token: details.token,
      spender: message.spender,
      amount: String(details.amount || "0"),
      deadline: Number(message.sigDeadline || details.expiration || 0),
      nonce: Number(details.nonce || 0),
    };
  }

  return null;
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

/**
 * Feature #45: VeroGuardProvider EIP-1193 Wrapper.
 */
export class VeroGuardProvider implements EIP1193Provider {
  private readonly provider: EIP1193Provider;
  private readonly config: Required<VeroGuardConfig>;

  constructor(provider: EIP1193Provider, config: VeroGuardConfig = {}) {
    this.provider = provider;
    this.config = {
      firewallUrl: config.firewallUrl || "http://127.0.0.1:8000",
      strictMode: config.strictMode ?? false,
      autoCapUnlimitedApprovals: config.autoCapUnlimitedApprovals ?? true,
      defaultSpendCap: config.defaultSpendCap || 1000n * 10n ** 18n,
      onWarning: config.onWarning || (async () => true),
      onBlocked: config.onBlocked || (() => {}),
    };
  }

  async request(args: RequestArguments): Promise<unknown> {
    const { method, params } = args;

    // Intercept transaction broadcast
    if (method === "eth_sendTransaction" || method === "eth_signTransaction") {
      const txParams = Array.isArray(params) ? { ...params[0] } : { ...params };
      if (txParams && typeof txParams === "object") {
        // Feature #17: Auto-cap unlimited approvals before broadcast
        if (this.config.autoCapUnlimitedApprovals && typeof txParams.data === "string") {
          const capResult = capUnlimitedApproval(txParams.data, this.config.defaultSpendCap);
          if (capResult.modified) {
            txParams.data = capResult.calldata;
          }
        }

        await this.interceptAndVerifyTransaction(txParams);
        return this.provider.request({ method, params: [txParams] });
      }
    }

    // Intercept EIP-712 permit signing (Feature #18)
    if (method === "eth_signTypedData_v4" || method === "eth_signTypedData") {
      const typedData = Array.isArray(params) && params.length > 1 ? params[1] : params;
      const permit = decodePermitTypedData(typedData);
      if (permit && (permit.amount === MAX_UINT256_HEX || permit.amount.startsWith("ffffffff"))) {
        if (this.config.strictMode) {
          throw new VeroSecurityError(
            `[VERO GUARD] Gasless permit grants UNLIMITED allowance to spender ${permit.spender}!`,
            "BLOCK",
            ["UNLIMITED_GASLESS_PERMIT"],
            ["Spender can drain all token balance without paying gas."]
          );
        }
      }
    }

    return this.provider.request(args);
  }

  private async interceptAndVerifyTransaction(tx: any): Promise<void> {
    const payload = {
      chain_id: tx.chainId ? Number(tx.chainId) : 1,
      safe_address: tx.from || "0x0000000000000000000000000000000000000000",
      to: tx.to || "0x0000000000000000000000000000000000000000",
      value: tx.value ? String(BigInt(tx.value)) : "0",
      data: tx.data || "0x",
      nonce: tx.nonce ? Number(tx.nonce) : 0,
    };

    let result: SimulationResult;

    try {
      const response = await fetch(`${this.config.firewallUrl}/v1/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Firewall returned HTTP ${response.status}`);
      }

      result = (await response.json()) as SimulationResult;
    } catch (err: any) {
      if (this.config.strictMode) {
        throw new VeroSecurityError(
          `Vero Firewall Unreachable in strict mode: ${err.message}`,
          "BLOCK",
          ["FIREWALL_OFFLINE"],
          ["Cannot verify transaction safety."]
        );
      }
      return;
    }

    if (result.decision === "BLOCK") {
      this.config.onBlocked(result.flags, result.deterministic_human_warnings);
      throw new VeroSecurityError(
        `[VERO BLOCKED] Dangerous transaction rejected: ${result.deterministic_human_warnings.join(" ")}`,
        result.decision,
        result.flags,
        result.deterministic_human_warnings
      );
    }

    if (result.decision === "WARN") {
      if (this.config.strictMode) {
        throw new VeroSecurityError(
          `[VERO STRICT] Warning triggered: ${result.deterministic_human_warnings.join(" ")}`,
          result.decision,
          result.flags,
          result.deterministic_human_warnings
        );
      }

      const confirmed = await this.config.onWarning(
        result.deterministic_human_warnings,
        result.four_word_checksum
      );

      if (!confirmed) {
        throw new VeroSecurityError(
          `User cancelled transaction after reviewing warnings [Checksum: ${result.four_word_checksum}]`,
          result.decision,
          result.flags,
          result.deterministic_human_warnings
        );
      }
    }
  }
}

export function createVeroGuard(provider: EIP1193Provider, config?: VeroGuardConfig): VeroGuardProvider {
  return new VeroGuardProvider(provider, config);
}
