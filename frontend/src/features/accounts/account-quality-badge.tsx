import { Info } from "lucide-react";
import { useTranslation } from "react-i18next";

import { badgeVariants } from "@/components/ui/badge";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import type { AccountDTO } from "@/features/accounts/accounts-api";
import { getAccountQualityState } from "@/features/accounts/account-quality";
import { cn } from "@/shared/lib/cn";
import { formatDateTime } from "@/shared/lib/format";

export function AccountQualityBadge({ account }: { account: AccountDTO }) {
  const { t, i18n } = useTranslation();
  const quality = getAccountQualityState(account);
  if (!quality) return null;

  const disabled = quality.kind === "disabled";
  const label = t(disabled ? "accounts.qualityDisabled" : "accounts.qualityHistory");

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={t("accounts.qualityDetails", { label })}
          className={cn(
            badgeVariants({ variant: disabled ? "destructive" : "outline" }),
            "min-h-6 cursor-pointer gap-1 whitespace-nowrap focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
            !disabled && "border-amber-500/40 text-amber-700 hover:bg-amber-500/10 dark:text-amber-300",
          )}
        >
          {label}<Info className="size-3" aria-hidden="true" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="max-w-[calc(100vw-2rem)] space-y-2 text-xs leading-relaxed" aria-label={label}>
        <p className="font-medium">{label}</p>
        <p>{t(disabled ? "accounts.qualityDisabledHelp" : "accounts.qualityHistoryHelp")}</p>
        {quality.cooldownUntil ? (
          <p className="text-muted-foreground">
            {t("accounts.qualityCooldownUntil")}<time dateTime={quality.cooldownUntil}>{formatDateTime(quality.cooldownUntil, i18n.language)}</time>
          </p>
        ) : null}
      </PopoverContent>
    </Popover>
  );
}
