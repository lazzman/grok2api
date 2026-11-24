import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { settingsSchema, toSettingsDTO, toSettingsForm } from "./settings-model.ts";
import type { SettingsConfigDTO } from "./settings-api.ts";

function sampleConfig(): SettingsConfigDTO {
  return {
    server: { maxConcurrentRequests: 64 },
    providerBuild: {
      baseURL: "https://build.example",
      fallbackBaseURL: "https://api.x.ai",
      clientVersion: "1.0.4",
      clientIdentifier: "grok-build",
      tokenAuth: "xai-grok-cli",
      tokenAuthConfigured: true,
      userAgent: "xai-grok-build/1.0.4",
      responseHeaderTimeout: "1m",
      streamIdleTimeout: "2m",
    },
    providerWeb: {
      baseURL: "https://grok.com",
      quotaTimeout: "15s",
      chatTimeout: "2m",
      streamIdleTimeout: "1m30s",
      imageTimeout: "2m",
      videoTimeout: "5m",
      freeVideoDurationCap: 6,
      mediaConcurrency: 4,
      recoveryBackoffBase: "5m",
      recoveryBackoffMax: "1h",
      allowNSFW: false,
      statsigMode: "manual",
      statsigManualConfigured: true,
      statsigSignerURL: "",
      clearanceMode: "manual",
      flareSolverrURL: "",
      clearanceTimeout: "30s",
      clearanceRefresh: "15m",
    },
    providerConsole: {
      baseURL: "https://api.x.ai",
      chatTimeout: "2m",
      streamIdleTimeout: "2m",
    },
    batch: {
      importConcurrency: 4,
      conversionConcurrency: 4,
      syncConcurrency: 4,
      refreshConcurrency: 4,
      randomDelay: "100ms",
    },
    media: {
      maxImageBytes: 10 * 1024 * 1024,
      maxTotalBytes: 1024 * 1024 * 1024,
      cleanupThresholdPercent: 80,
      cleanupInterval: "10m",
    },
    frontend: { publicApiBaseURL: "" },
    routing: {
      stickyTTL: "1h",
      cooldownBase: "1m",
      cooldownMax: "30m",
      capacityWait: "5s",
      maxAttempts: 6,
      videoMaxAttempts: 3,
      preferFreeBuild: false,
      markBuildChatDeniedAsReauth: false,
      accountIsolatedConnections: false,
      segmentedSelector: { enabled: true, minCandidates: 3000, windowSize: 64 },
    },
    audit: {
      bufferSize: 4096,
      batchSize: 128,
      flushInterval: "1s",
      commitDelayMS: 5,
      retentionDays: 7,
    },
    clientKeyDefaults: { rpmLimit: 60, maxConcurrent: 4 },
    accounts: {
      autoDisableDegradedAccounts: false,
      qualityHedgeEnabled: true,
      qualityHedgeDelay: "8s",
      qualityHedgeMaxConcurrent: 2,
      markBuildForbiddenReauth: false,
      buildForbiddenReauthCodes: ["permission-denied"],
      excludeBuildBotFlaggedFromScheduling: false,
      autoDeleteConsoleUnlinked: false,
      autoCleanReauthEnabled: false,
      autoCleanReauthInterval: "10m",
      autoCleanReauthMinAge: "1h",
      autoCleanIncludeDisabled: false,
    },
  };
}

describe("settings-model quality hedge fields", () => {
  it("round-trips quality hedge settings between DTO and form", () => {
    const form = toSettingsForm(sampleConfig());
    assert.equal(form.accounts.qualityHedgeEnabled, true);
    assert.deepEqual(form.accounts.qualityHedgeDelay, { value: 8, unit: "s" });
    assert.equal(form.accounts.qualityHedgeMaxConcurrent, 2);

    const parsed = settingsSchema.safeParse(form);
    assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues));

    const dto = toSettingsDTO(form);
    assert.equal(dto.accounts.qualityHedgeEnabled, true);
    assert.equal(dto.accounts.qualityHedgeDelay, "8s");
    assert.equal(dto.accounts.qualityHedgeMaxConcurrent, 2);
  });

  it("rejects out-of-range hedge delay and concurrency", () => {
    const tooLongDelay = toSettingsForm(sampleConfig());
    tooLongDelay.accounts.qualityHedgeDelay = { value: 31, unit: "s" };
    assert.equal(settingsSchema.safeParse(tooLongDelay).success, false);

    const tooLowConcurrency = toSettingsForm(sampleConfig());
    tooLowConcurrency.accounts.qualityHedgeMaxConcurrent = 1;
    assert.equal(settingsSchema.safeParse(tooLowConcurrency).success, false);

    const tooHighConcurrency = toSettingsForm(sampleConfig());
    tooHighConcurrency.accounts.qualityHedgeMaxConcurrent = 7;
    assert.equal(settingsSchema.safeParse(tooHighConcurrency).success, false);
  });
});
