import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { getAccountQualityState } from "./account-quality.ts";

const now = Date.parse("2026-11-26T08:00:00Z");
const cooldownUntil = "2026-11-26T20:00:00Z";

describe("账号降智标签", () => {
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
