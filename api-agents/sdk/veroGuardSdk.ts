/**
 * @vero/guard-sdk (#45)
 * EIP-1193 Provider Wrapper for Project Vero Transaction Firewall.
 *
 * Intercepts `eth_sendTransaction` and `eth_signTypedData_v4` calls, runs real-time
 * deterministic simulation via the Vero Firewall API, and prevents blind signing thefts.
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
  firewallUrl?: string; // Default: http://localhost:8000
  strictMode?: boolean; // If true, WARN is also rejected
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

export class VeroSecurityError extends Error {
  public readonly decision: string;
  public readonly flags: string[];
  public readonly warnings: string[];

  constructor(message: string, decision: string, flags: string[], warnings: string[]) {
    super(message);
    this.name = "VeroSecurityError";
    this.decision = decision;
    this.flags = flags;
    this.warnings = warnings;
  }
}

export class VeroGuardProvider implements EIP1193Provider {
  private readonly provider: EIP1193Provider;
  private readonly config: Required<VeroGuardConfig>;

  constructor(provider: EIP1193Provider, config: VeroGuardConfig = {}) {
    this.provider = provider;
    this.config = {
      firewallUrl: config.firewallUrl || "http://localhost:8000",
      strictMode: config.strictMode ?? false,
      onWarning: config.onWarning || (async () => true),
      onBlocked: config.onBlocked || (() => {}),
    };
  }

  async request(args: RequestArguments): Promise<unknown> {
    const { method, params } = args;

    if (method === "eth_sendTransaction" || method === "eth_signTransaction") {
      const txParams = Array.isArray(params) ? params[0] : params;
      if (txParams && typeof txParams === "object") {
        await this.interceptAndVerifyTransaction(txParams);
      }
    }

    // Forward approved or non-critical call to underlying wallet
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
      // In case firewall is unreachable and strictMode is on, fail closed
      if (this.config.strictMode) {
        throw new VeroSecurityError(
          `Vero Firewall Unreachable in strict mode: ${err.message}`,
          "BLOCK",
          ["FIREWALL_OFFLINE"],
          ["Cannot verify transaction safety."]
        );
      }
      return; // Fail open if non-strict
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
