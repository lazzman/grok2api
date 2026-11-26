import type { AccountDTO } from "./accounts-api";

type AccountQualityState = {
  kind: "history" | "disabled";
  cooldownUntil?: string;
};

export function getAccountQualityQuarantine(
  account: Pick<AccountDTO, "enabled" | "authStatus" | "leaseQuarantinedUntil" | "leaseQuarantineReason" | "leaseQuarantineNodeId">,
  now = Date.now(),
) {
  const cooldownUntil = account.leaseQuarantinedUntil;
  if (!cooldownUntil) return null;
  const deadline = Date.parse(cooldownUntil);
  if (!account.enabled || account.authStatus !== "active" || !Number.isFinite(deadline) || deadline <= now) return null;

  return { kind: "quarantined" as const, cooldownUntil, reason: account.leaseQuarantineReason, nodeId: account.leaseQuarantineNodeId };
}

export function getAccountQualityState(
  account: Pick<AccountDTO, "enabled" | "lastError" | "cooldownUntil" | "qualityHistory">,
  now = Date.now(),
): AccountQualityState | null {
  if (account.lastError !== "missing_thinking" && account.lastError !== "missing_thinking_disabled" && !(account.qualityHistory && account.qualityHistory.hits > 0)) return null;

  return {
    kind: account.lastError === "missing_thinking_disabled" && !account.enabled ? "disabled" : "history",
    cooldownUntil: account.cooldownUntil && Date.parse(account.cooldownUntil) > now ? account.cooldownUntil : undefined,
  };
}
