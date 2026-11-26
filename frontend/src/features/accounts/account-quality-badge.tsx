import { Info } from "lucide-react";
import { useTranslation } from "react-i18next";

import { badgeVariants } from "@/components/ui/badge";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import type { AccountDTO, AccountQualityHistory } from "@/features/accounts/accounts-api";
import { getAccountQualityQuarantine, getAccountQualityState } from "@/features/accounts/account-quality";
import { cn } from "@/shared/lib/cn";
import { formatDateTime } from "@/shared/lib/format";

export function AccountQualityBadge({ account, historyWindow }: { account: AccountDTO; historyWindow: string }) {
  const strike = getAccountQualityState(account);
  const quarantine = getAccountQualityQuarantine(account);
  const quality = quarantine ?? strike;
  if (!quality) return null;
  return (
    <QualityBadge quality={quality} history={account.qualityHistory} historyWindow={historyWindow} thinkingStrike={account.lastError === "missing_thinking" || account.lastError === "missing_thinking_disabled"} />
  );
}

function QualityBadge({ quality, history, historyWindow, thinkingStrike }: {
  quality: NonNullable<ReturnType<typeof getAccountQualityState> | ReturnType<typeof getAccountQualityQuarantine>>;
  history?: AccountQualityHistory;
  historyWindow?: string;
  thinkingStrike?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const disabled = quality.kind === "disabled";
  const quarantined = quality.kind === "quarantined";
  const label = t(quarantined ? (history || thinkingStrike ? "accounts.qualityHistoryQuarantined" : "accounts.qualityQuarantined") : disabled ? "accounts.qualityDisabled" : "accounts.qualityHistory");

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={t("accounts.qualityDetails", { label })}
          className={cn(
            badgeVariants({ variant: disabled ? "destructive" : "outline" }),
            "min-h-6 max-w-full cursor-pointer gap-1 whitespace-nowrap focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
            !disabled && "border-amber-500/40 text-amber-700 hover:bg-amber-500/10 dark:text-amber-300",
          )}
        >
          <span className="truncate">{label}</span><Info className="size-3 shrink-0" aria-hidden="true" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="max-w-[calc(100vw-2rem)] space-y-2 text-xs leading-relaxed" aria-label={label}>
        <p className="font-medium">{label}</p>
        <p>{t(quarantined ? "accounts.qualityQuarantinedHelp" : disabled ? "accounts.qualityDisabledHelp" : thinkingStrike ? "accounts.qualityHistoryHelp" : "accounts.qualityAuditHistoryHelp")}</p>
        {quarantined && thinkingStrike ? <p>{t("accounts.qualityHistoryHelp")}</p> : null}
        {history ? (
          <>
            <p>{t("accounts.qualityHistoryCount", { window: historyWindow, count: history.hits })}</p>
            <p className="text-muted-foreground">soft {history.soft} · hard {history.hard} · burst {history.burst} · thinking {history.thinking}</p>
            <p className="text-muted-foreground">{t("accounts.qualityLastHit", { time: formatDateTime(history.last, i18n.language) })}</p>
          </>
        ) : null}
        {quality.kind === "quarantined" ? (
          <p className="text-muted-foreground">
            {t("accounts.qualityLeaseReason", { reason: t(`qualityGuard.reasons.${quality.reason || "unknown"}`, { defaultValue: quality.reason }), node: quality.nodeId || "-" })}
          </p>
        ) : null}
        {quality.cooldownUntil ? (
          <p className="text-muted-foreground">
            {t(quarantined ? "accounts.qualityQuarantineUntil" : "accounts.qualityCooldownUntil")}<time dateTime={quality.cooldownUntil}>{formatDateTime(quality.cooldownUntil, i18n.language)}</time>
          </p>
        ) : null}
      </PopoverContent>
    </Popover>
  );
}
