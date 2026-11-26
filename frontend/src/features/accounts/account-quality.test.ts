import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { getAccountQualityQuarantine, getAccountQualityState } from "./account-quality.ts";

const now = Date.parse("2026-11-26T08:00:00Z");
const cooldownUntil = "2026-11-26T20:00:00Z";

describe("账号降智标签", () => {
  it("速率历史命中无需隔离或缺思考标记即可显示曾降智", () => {
    for (const kind of ["soft", "hard", "burst", "thinking"] as const) {
      for (const enabled of [true, false]) {
        assert.equal(getAccountQualityState({ enabled, qualityHistory: { hits: 1, soft: 0, hard: 0, burst: 0, thinking: 0, last: "2026-11-26T07:00:00Z", [kind]: 1 } }, now)?.kind, "history");
      }
    }
  });

  it("零次命中不显示降智，已有停用标记不被历史覆盖", () => {
    const qualityHistory = { hits: 0, soft: 0, hard: 0, burst: 0, thinking: 0, last: "2026-11-26T07:00:00Z" };
    assert.equal(getAccountQualityState({ enabled: true, qualityHistory }, now), null);
    assert.equal(getAccountQualityState({ enabled: false, lastError: "missing_thinking_disabled", qualityHistory: { ...qualityHistory, hits: 1, hard: 1 } }, now)?.kind, "disabled");
  });

  it("无缺思考标记时仍展示质量守护的速率隔离", () => {
    for (const reason of ["soft_tps", "hard_tps", "buffered_burst"]) {
      assert.deepEqual(getAccountQualityQuarantine({
        enabled: true, authStatus: "active", leaseQuarantinedUntil: cooldownUntil, leaseQuarantineReason: reason, leaseQuarantineNodeId: "7",
      }, now), { kind: "quarantined", cooldownUntil, reason, nodeId: "7" });
    }
  });

  it("隔离和缺思考历史可以同时展示，互不覆盖", () => {
    const account = { enabled: true, authStatus: "active" as const, lastError: "missing_thinking", leaseQuarantinedUntil: cooldownUntil };
    assert.equal(getAccountQualityState(account, now)?.kind, "history");
    assert.equal(getAccountQualityQuarantine(account, now)?.kind, "quarantined");
  });

  it("忽略过期、无效或已解除的隔离", () => {
    for (const deadline of [undefined, "", "invalid", "2026-11-26T07:00:00Z", "2026-11-26T08:00:00Z"]) {
      assert.equal(getAccountQualityQuarantine({ enabled: true, authStatus: "active", leaseQuarantinedUntil: deadline }, now), null);
    }
    assert.equal(getAccountQualityQuarantine({ enabled: false, authStatus: "active", leaseQuarantinedUntil: cooldownUntil }, now), null);
    assert.equal(getAccountQualityQuarantine({ enabled: true, authStatus: "reauthRequired", leaseQuarantinedUntil: cooldownUntil }, now), null);
  });

  it("首次降智显示历史标记和有效冷却截止时间", () => {
    assert.deepEqual(getAccountQualityState({ enabled: true, lastError: "missing_thinking", cooldownUntil }, now), {
      kind: "history", cooldownUntil,
    });
  });

  it("冷却到期或被清除后仍保留历史标记", () => {
    for (const deadline of [undefined, "2026-11-26T07:00:00Z", "2026-11-26T08:00:00Z", "invalid"]) {
      assert.deepEqual(getAccountQualityState({ enabled: true, lastError: "missing_thinking", cooldownUntil: deadline }, now), {
        kind: "history", cooldownUntil: undefined,
      });
    }
  });

  it("仅在已停用且有降智停用标记时显示降智停用", () => {
    assert.equal(getAccountQualityState({ enabled: false, lastError: "missing_thinking_disabled" }, now)?.kind, "disabled");
    assert.equal(getAccountQualityState({ enabled: false, lastError: "missing_thinking" }, now)?.kind, "history");
  });

  it("人工重新启用后显示曾降智而不是仍被停用", () => {
    assert.equal(getAccountQualityState({ enabled: true, lastError: "missing_thinking_disabled" }, now)?.kind, "history");
  });

  it("正常账号及其他故障冷却不会被标成降智", () => {
    for (const lastError of [undefined, "", "upstream status 504", "quality_degraded", "missing_thinking_other"]) {
      for (const enabled of [true, false]) {
        assert.equal(getAccountQualityState({ enabled, lastError, cooldownUntil }, now), null);
      }
    }
  });
});
