import type { AccountDTO } from "./accounts-api";

type AccountQualityState = {
  kind: "history" | "disabled";
  cooldownUntil?: string;
};

export function getAccountQualityState(
  account: Pick<AccountDTO, "enabled" | "lastError" | "cooldownUntil">,
  now = Date.now(),
): AccountQualityState | null {
  if (account.lastError !== "missing_thinking" && account.lastError !== "missing_thinking_disabled") return null;

  return {
    kind: account.lastError === "missing_thinking_disabled" && !account.enabled ? "disabled" : "history",
    cooldownUntil: account.cooldownUntil && Date.parse(account.cooldownUntil) > now ? account.cooldownUntil : undefined,
  };
}
