package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	inferencedomain "github.com/chenyme/grok2api/backend/internal/domain/inference"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	neterrorpkg "github.com/chenyme/grok2api/backend/internal/pkg/neterror"
)

const (
	ErrorQualityDegraded                   = "quality_degraded"
	qualityRetryFailOpen                   = "fail_open"
	qualityRetryFailClosed                 = "fail_closed"
	defaultQualityMaxAttempts              = 6
	defaultQualityHoldTimeout              = 30 * time.Second
	defaultQualityMinOutput                = int64(8)
	defaultMinEncryptedBytes               = 256
	defaultEncryptedBytesPerReasoningToken = 4
	defaultBurstMinReasoning               = int64(80)
	// 短窗爆吐检测阈值：用于拦截 2s 内高推理占比爆吐及极短正文虚报大推理账单的降智响应。
	defaultFakeEncFlushMS = int64(2000)
	defaultMissingThinkingCooldown   = 12 * time.Hour
	lastErrorMissingThinking         = accountdomain.LastErrorMissingThinking
	lastErrorMissingThinkingDisabled = accountdomain.LastErrorMissingThinkingDisabled
	// An empty stream that idles while held is treated as an account-quality
	// failure: the request can still rotate before any bytes reach the client.
	qualityIdleAccountCooldown = 15 * time.Minute
)

var (
	errQualityDegraded    = errors.New("上游响应缺少推理")
	errQualityEmptyStream = errors.New("上游流式响应为空")
)

// QualityRetryRuntime is the isolated request-path withhold/retry policy.
// Zero Enabled leaves production behavior unchanged.
type QualityRetryRuntime struct {
	Enabled         bool
	MaxAttempts     int
	HoldTimeout     time.Duration
	MinOutputTokens int64
	OnExhausted     string
	AutoDisable     bool
	AccountCooldown time.Duration
	// IdleAccountCooldown is applied to truly empty upstream streams
	// (idle timeout / empty peek). Missing-thinking still uses AccountCooldown.
	IdleAccountCooldown             time.Duration
	MinEncryptedBytes               int
	EncryptedBytesPerReasoningToken int
	SoftTPS                         float64
	HardTPS                         float64
	MinGenerationMS                 int64
	FailClosed                      bool
}

// QualityStreamSignals is the hold classifier input. Tests drive this
// directly and via ObserveQualityChunk on SSE fixtures.
type QualityStreamSignals struct {
	HasThinking       bool `json:"has_thinking"`
	HasReasoningDelta bool `json:"has_reasoning_delta"`
	// ReasoningStarted is an empty reasoning item or the Chat SSE stub
	// `: grok2api-reasoning-start`. That is not proof of thinking: 降智
	// still emits the stub, then dumps visible tokens with usage 0.
	ReasoningStarted bool  `json:"reasoning_started"`
	HasToolCall      bool  `json:"has_tool_call"`
	VisibleTokens    int64 `json:"visible_tokens"`
	ReasoningTokens  int64 `json:"reasoning_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	EncryptedBytes   int   `json:"encrypted_bytes"`
	EncryptedFloor   int64 `json:"encrypted_floor"`
	UsageReported    bool  `json:"usage_reported"`
	FirstVisible     bool  `json:"first_visible"`
	VisibleFlushMS   int64 `json:"visible_flush_ms"`
	Terminal         bool  `json:"terminal"`
	HoldExpired      bool  `json:"hold_expired"`
}

// QualityWithholdReason 标识流式质量闸门扣留响应的具体规则分支，用于日志与诊断定位。
type QualityWithholdReason string

const (
	QualityWithholdNone                  QualityWithholdReason = ""
	QualityWithholdHoldExpiredShort      QualityWithholdReason = "hold_expired_short_visible"
	QualityWithholdFakeEncryptedBurst    QualityWithholdReason = "fake_encrypted_burst"
	QualityWithholdPlaintextRatioBurst   QualityWithholdReason = "plaintext_ratio_burst"
	QualityWithholdMissingThinkingStream QualityWithholdReason = "missing_thinking_stream"
	QualityWithholdMissingThinkingTerm   QualityWithholdReason = "missing_thinking_terminal"
	QualityWithholdMissingThinkingExpire QualityWithholdReason = "missing_thinking_hold_expired"
)

// QualityPeekDiagnostic 保存质量闸门做出裁决时的协议、命中的规则原因与关键信号快照。
type QualityPeekDiagnostic struct {
	Protocol        string                `json:"protocol"`
	Reason          QualityWithholdReason `json:"reason,omitempty"`
	MinOutputTokens int64                 `json:"min_output_tokens"`
	Signals         QualityStreamSignals  `json:"signals"`
}

// QualityVerdict is the hold decision for one upstream stream.
type QualityVerdict string

const (
	QualityWait     QualityVerdict = "wait"
	QualityDeliver  QualityVerdict = "deliver"
	QualityWithhold QualityVerdict = "withhold"
)

// QualityRetryAction is what the attempt loop does with a withhold verdict.
type QualityRetryAction string

const (
	QualityActionDeliver     QualityRetryAction = "deliver"
	QualityActionDeliverLast QualityRetryAction = "deliver_last"
	QualityActionRetry       QualityRetryAction = "retry"
	QualityActionReject      QualityRetryAction = "reject"
)

func normalizeQualityRetry(cfg QualityRetryRuntime) QualityRetryRuntime {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultQualityMaxAttempts
	}
	if cfg.HoldTimeout <= 0 {
		cfg.HoldTimeout = defaultQualityHoldTimeout
	}
	if cfg.MinOutputTokens <= 0 {
		cfg.MinOutputTokens = defaultQualityMinOutput
	}
	if cfg.AccountCooldown <= 0 {
		cfg.AccountCooldown = defaultMissingThinkingCooldown
	}
	if cfg.IdleAccountCooldown <= 0 {
		cfg.IdleAccountCooldown = qualityIdleAccountCooldown
	}
	if cfg.MinEncryptedBytes <= 0 {
		cfg.MinEncryptedBytes = defaultMinEncryptedBytes
	}
	if cfg.EncryptedBytesPerReasoningToken <= 0 {
		cfg.EncryptedBytesPerReasoningToken = defaultEncryptedBytesPerReasoningToken
	}
	if cfg.SoftTPS <= 0 {
		cfg.SoftTPS = audit.DefaultDegradeSoftTPS
	}
	if cfg.HardTPS <= cfg.SoftTPS {
		cfg.HardTPS = audit.DefaultDegradeHardTPS
	}
	if cfg.MinGenerationMS <= 0 {
		cfg.MinGenerationMS = audit.DefaultDegradeMinGenMS
	}
	cfg.OnExhausted = normalizeQualityExhaustionPolicy(cfg.OnExhausted)
	return cfg
}

func (s *Service) UpdateQualityRetry(cfg QualityRetryRuntime) {
	normalized := normalizeQualityRetry(cfg)
	s.qualityRetry.Store(&normalized)
}

func (s *Service) qualityRetryConfig() QualityRetryRuntime {
	if s == nil {
		return normalizeQualityRetry(QualityRetryRuntime{})
	}
	if value := s.qualityRetry.Load(); value != nil {
		return *value
	}
	return normalizeQualityRetry(QualityRetryRuntime{})
}

// encryptedThinkingFloor is max(minBytes, reasoningTokens*bytesPerToken).
// A non-empty stub such as "gAAAA-cipher" is not thinking.
func encryptedThinkingFloor(minBytes, bytesPerToken int, reasoningTokens int64) int64 {
	if minBytes <= 0 {
		minBytes = defaultMinEncryptedBytes
	}
	if bytesPerToken <= 0 {
		bytesPerToken = defaultEncryptedBytesPerReasoningToken
	}
	floor := int64(minBytes)
	if reasoningTokens > 0 {
		if reasoningTokens > math.MaxInt64/int64(bytesPerToken) {
			return math.MaxInt64
		}
		need := reasoningTokens * int64(bytesPerToken)
		if need > floor {
			floor = need
		}
	}
	return floor
}

func qualityFastFlush(sig QualityStreamSignals, limitMS int64) bool {
	return sig.FirstVisible && sig.VisibleFlushMS >= 0 && sig.VisibleFlushMS < limitMS
}

func classifyQualityFastReasoningRatioDump(sig QualityStreamSignals) QualityWithholdReason {
	if !sig.HasReasoningDelta {
		return QualityWithholdNone
	}
	if !qualityFastFlush(sig, defaultFakeEncFlushMS) {
		return QualityWithholdNone
	}
	output := sig.OutputTokens
	if output <= 0 {
		output = sig.VisibleTokens + sig.ReasoningTokens
	}
	if output <= 0 || sig.ReasoningTokens <= 0 {
		return QualityWithholdNone
	}
	if sig.ReasoningTokens*5 >= output*4 {
		return QualityWithholdPlaintextRatioBurst
	}
	return QualityWithholdNone
}

// ClassifyQualityHold 判定当前扣留的流式响应应继续等待、放行还是按降智扣留。
func ClassifyQualityHold(sig QualityStreamSignals, minOutput int64) QualityVerdict {
	verdict, _ := ClassifyQualityHoldWithReason(sig, minOutput)
	return verdict
}

// ClassifyQualityHoldWithReason 执行「无思考明文即降智、纯工具与极短回复放行」规则并返回具体原因：
//  1. 收到思考明文（HasReasoningDelta）：仅保留 2s 内高推理占比爆吐拦截，其余立即放行；
//  2. 无思考明文时，纯客户端工具调用（或未超时前仅带极短前缀的工具调用）放行；
//  3. 无思考明文且极短正文却虚报大推理账单（reasoning_tokens >= 80）直接扣留；
//  4. 无思考明文且可见正文达到 minOutput（不再认可纯密文 encrypted_content）直接扣留；
//  5. 复用 holdTimeout：超时仍无思考明文（含 0 输出静默、空占位或纯密文）直接扣留；
//  6. 未超时且已结束的极短回复（0 < output < minOutput）放行，空流交由传输错误处理。
func ClassifyQualityHoldWithReason(sig QualityStreamSignals, minOutput int64) (QualityVerdict, QualityWithholdReason) {
	if minOutput <= 0 {
		minOutput = defaultQualityMinOutput
	}
	if sig.HasReasoningDelta {
		if reason := classifyQualityFastReasoningRatioDump(sig); reason != QualityWithholdNone {
			return QualityWithhold, reason
		}
		return QualityDeliver, QualityWithholdNone
	}
	if sig.HasToolCall && (sig.VisibleTokens == 0 || (sig.VisibleTokens < minOutput && !sig.HoldExpired)) {
		return QualityDeliver, QualityWithholdNone
	}
	output := sig.VisibleTokens
	if output <= 0 && sig.Terminal && !sig.HasToolCall {
		output = sig.OutputTokens
	}
	enough := output >= minOutput
	heavyReasoning := sig.ReasoningTokens >= defaultBurstMinReasoning
	shortVisible := sig.VisibleTokens > 0 && sig.VisibleTokens < minOutput
	if shortVisible && heavyReasoning {
		if sig.HoldExpired {
			return QualityWithhold, QualityWithholdHoldExpiredShort
		}
		if sig.Terminal || qualityFastFlush(sig, defaultFakeEncFlushMS) {
			return QualityWithhold, QualityWithholdFakeEncryptedBurst
		}
	}
	if enough {
		if sig.Terminal {
			return QualityWithhold, QualityWithholdMissingThinkingTerm
		}
		if sig.HoldExpired {
			return QualityWithhold, QualityWithholdMissingThinkingExpire
		}
		return QualityWithhold, QualityWithholdMissingThinkingStream
	}
	if sig.HoldExpired {
		return QualityWithhold, QualityWithholdMissingThinkingExpire
	}
	if sig.Terminal {
		if output <= 0 {
			return QualityWait, QualityWithholdNone
		}
		return QualityDeliver, QualityWithholdNone
	}
	return QualityWait, QualityWithholdNone
}

func qualityDiagnosticTransportError(reason QualityWithholdReason) string {
	if reason == QualityWithholdNone {
		return ErrorQualityDegraded
	}
	return ErrorQualityDegraded + ": " + string(reason)
}

func marshalQualityDiagnostic(diag QualityPeekDiagnostic) []byte {
	if diag.Protocol == "" && diag.Reason == QualityWithholdNone && diag.MinOutputTokens == 0 && diag.Signals == (QualityStreamSignals{}) {
		return nil
	}
	raw, err := json.Marshal(diag)
	if err != nil {
		return nil
	}
	return raw
}

func qualityDiagnosticLogAttrs(diag QualityPeekDiagnostic) []any {
	sig := diag.Signals
	return []any{
		"reason", string(diag.Reason),
		"protocol", diag.Protocol,
		"min_output_tokens", diag.MinOutputTokens,
		"has_thinking", sig.HasThinking,
		"has_reasoning_delta", sig.HasReasoningDelta,
		"reasoning_started", sig.ReasoningStarted,
		"has_tool_call", sig.HasToolCall,
		"visible_tokens", sig.VisibleTokens,
		"reasoning_tokens", sig.ReasoningTokens,
		"output_tokens", sig.OutputTokens,
		"encrypted_bytes", sig.EncryptedBytes,
		"encrypted_floor", sig.EncryptedFloor,
		"visible_flush_ms", sig.VisibleFlushMS,
		"hold_expired", sig.HoldExpired,
		"terminal", sig.Terminal,
	}
}

// qualityPeekAbortError prefers the idle-timeout cause over a plain
// context.Canceled so the attempt loop can retry instead of treating the
// abort as a client 499.
func qualityPeekAbortError(ctx context.Context, err error) error {
	if ctx != nil {
		if cause := context.Cause(ctx); neterrorpkg.IsUpstreamStreamIdleTimeout(cause) {
			return cause
		}
	}
	if neterrorpkg.IsUpstreamStreamIdleTimeout(err) {
		return err
	}
	if err != nil {
		return err
	}
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

// isClientRequestCancel reports a real client disconnect. Upstream idle
// timeouts cancel the same context and must not be classified as 499.
func isClientRequestCancel(ctx context.Context, err error) bool {
	return neterrorpkg.IsClientRequestCancel(ctx, err)
}

// DecideQualityRetry caps withhold recovery at maxAttempts (default 6:
// original + five extra accounts). The last withhold
// (attemptIndex == maxAttempts-1) is fail-open unless OnExhausted is fail_closed.
func DecideQualityRetry(verdict QualityVerdict, attemptIndex, maxAttempts int, onExhausted string) QualityRetryAction {
	if verdict != QualityWithhold {
		return QualityActionDeliver
	}
	if maxAttempts <= 0 {
		maxAttempts = defaultQualityMaxAttempts
	}
	if attemptIndex < 0 {
		attemptIndex = 0
	}
	if attemptIndex < maxAttempts-1 {
		return QualityActionRetry
	}
	// attemptIndex == maxAttempts-1 (or past it): do not retry again.
	if normalizeQualityExhaustionPolicy(onExhausted) == qualityRetryFailClosed {
		return QualityActionReject
	}
	return QualityActionDeliverLast
}

// BoundQualityRetry turns a Retry into DeliverLast/Reject when the routing
// loop has no remaining account slot, so the already-held body is not dropped
// on continue-into-exhausted-loop.
func BoundQualityRetry(action QualityRetryAction, hasNextRoutingAttempt bool, onExhausted string) QualityRetryAction {
	if action != QualityActionRetry || hasNextRoutingAttempt {
		return action
	}
	if normalizeQualityExhaustionPolicy(onExhausted) == qualityRetryFailClosed {
		return QualityActionReject
	}
	return QualityActionDeliverLast
}

func normalizeQualityExhaustionPolicy(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), qualityRetryFailOpen) {
		return qualityRetryFailOpen
	}
	return qualityRetryFailClosed
}

// QualityCommit is the single attempt-loop decision for a held stream.
type QualityCommit struct {
	Action   QualityRetryAction
	Audit    bool
	KeepBody bool
}

// CommitQualityHold is the shipped withhold/retry/commit unit. The attempt
// loop must not re-derive this from Decide+Bound+switch.
func CommitQualityHold(verdict QualityVerdict, qualityAttempt, maxAttempts int, hasNextRouting bool, onExhausted string) QualityCommit {
	action := BoundQualityRetry(
		DecideQualityRetry(verdict, qualityAttempt, maxAttempts, onExhausted),
		hasNextRouting,
		onExhausted,
	)
	switch action {
	case QualityActionRetry, QualityActionReject:
		return QualityCommit{Action: action, Audit: true, KeepBody: false}
	case QualityActionDeliverLast:
		return QualityCommit{Action: action, Audit: false, KeepBody: true}
	default:
		return QualityCommit{Action: QualityActionDeliver, Audit: false, KeepBody: true}
	}
}

func shouldHoldQualityStream(input Input, ownership *inferencedomain.ResponseOwnership, route modeldomain.Route, operation audit.Operation, cfg QualityRetryRuntime) bool {
	if !cfg.Enabled || !input.Streaming || input.ForcedEgressNodeID != 0 || input.skipQualityHold {
		return false
	}
	switch operation {
	case audit.OperationChat, audit.OperationResponses, audit.OperationMessages, "":
	default:
		return false
	}
	// Context compaction is a system summary operation, not a normal reasoning
	// turn. Holding it can quarantine a healthy account for producing the
	// expected summary without streamed reasoning. Keep both compaction forms
	// excluded even if a caller reaches this gate without skipQualityHold.
	if isResponsesCompactionRequest(input.Body) {
		return false
	}
	if route.Provider != accountdomain.ProviderBuild && route.Provider != accountdomain.ProviderConsole {
		return false
	}
	// TUI commonly declares tools and follow-ups carry previous_response_id.
	// They still need quality classification, but replay safety is decided
	// separately: detecting a degraded response must not imply that an
	// account-bound or side-effecting request can run on another account.
	if qualityRequestDisablesReasoning(input.Body) {
		return false
	}
	if modeldomain.SupportsReasoningForProvider(route.Provider, input.PublicModel) {
		return true
	}
	return modeldomain.SupportsReasoningForProvider(route.Provider, route.UpstreamModel)
}

// canReplayQualityHoldAcrossAccounts separates response classification from
// retry authority. Stored Responses are account-bound, while hosted tools may
// already have produced an external side effect before their held response is
// rejected. Both may be held, audited, and penalized, but neither is replayed
// on another account.
func canReplayQualityHoldAcrossAccounts(input Input, ownership *inferencedomain.ResponseOwnership) bool {
	return ownership == nil && !qualityRequestHasReplayUnsafeHostedTools(input.Body)
}

func qualityRequestHasReplayUnsafeHostedTools(body []byte) bool {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil || payload == nil {
		return false
	}
	if raw, exists := payload["web_search_options"]; exists && raw != nil {
		return true
	}
	if raw, exists := payload["mcp_servers"]; exists && raw != nil {
		servers, ok := raw.([]any)
		if !ok || len(servers) > 0 {
			return true
		}
	}
	if qualityToolListHasReplayUnsafeHostedTool(payload["tools"]) {
		return true
	}
	// Responses Tool Search can load declarations later in the request. Only
	// inspect additional_tools items; arbitrary user/schema objects may also
	// contain a field named "tools" and must not affect the retry policy.
	items, _ := payload["input"].([]any)
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok || jsonNodeString(item["type"]) != "additional_tools" {
			continue
		}
		if qualityToolListHasReplayUnsafeHostedTool(item["tools"]) {
			return true
		}
	}
	return false
}

func qualityToolListHasReplayUnsafeHostedTool(value any) bool {
	tools, ok := value.([]any)
	if !ok {
		return false
	}
	for _, rawTool := range tools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			continue
		}
		kind := jsonNodeString(tool["type"])
		switch kind {
		case "", "function", "custom", "local_shell", "apply_patch", "tool_search":
			// These declarations only ask the model to return a call. Execution
			// happens in the client after the held response is committed.
			continue
		case "shell":
			environment, _ := tool["environment"].(map[string]any)
			if jsonNodeString(environment["type"]) != "local" {
				return true
			}
		case "namespace":
			if qualityToolListHasReplayUnsafeHostedTool(tool["tools"]) {
				return true
			}
		default:
			// Default to no replay for every server/native tool, including types
			// added by future protocol versions that this gateway does not know yet.
			return true
		}
	}
	return false
}

func jsonNodeString(value any) string {
	text, _ := value.(string)
	return strings.ToLower(strings.TrimSpace(text))
}

func qualityRequestDisablesReasoning(body []byte) bool {
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	if jsonStringEquals(payload["reasoning_effort"], modeldomain.ReasoningEffortNone) {
		return true
	}
	for _, key := range []string{"reasoning", "output_config", "thinking"} {
		var nested map[string]json.RawMessage
		if json.Unmarshal(payload[key], &nested) != nil {
			continue
		}
		if jsonStringEquals(nested["effort"], modeldomain.ReasoningEffortNone) || jsonStringEquals(nested["type"], "disabled") {
			return true
		}
		var budget int64
		if raw, ok := nested["budget_tokens"]; ok && json.Unmarshal(raw, &budget) == nil && budget == 0 {
			return true
		}
	}
	return jsonStringEquals(payload["thinking"], "disabled")
}

func jsonStringEquals(raw json.RawMessage, want string) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && strings.EqualFold(strings.TrimSpace(value), want)
}

func (s *Service) applyMissingThinkingPenalty(ctx context.Context, requestID string, credential accountdomain.Credential, cooldown time.Duration, autoDisable bool) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalizationTimeout)
	defer cancel()
	action, err := s.selector.markMissingThinking(writeCtx, credential, cooldown, autoDisable)
	if err != nil {
		s.logger.Error("quality_degraded_penalty_failed", "request_id", requestID, "account_id", credential.ID, "action", action, "error", err)
		return
	}
	switch action {
	case missingThinkingPenaltyDisabled:
		s.logger.Info("quality_degraded_disabled", "request_id", requestID, "account_id", credential.ID)
	case missingThinkingPenaltyCooled:
		s.logger.Info("quality_degraded_cooldown", "request_id", requestID, "account_id", credential.ID, "cooldown", cooldown.String())
	}
}

func (s *Service) applyOutputSpeedPenalty(ctx context.Context, record audit.Record, credential accountdomain.Credential, cfg QualityRetryRuntime, forcedEgress bool) error {
	// Both explicit and TUI compaction are classified in the audit record.
	// System summaries stay exempt from account quality penalties.
	if record.Operation == audit.OperationCompaction {
		return nil
	}
	if !cfg.Enabled || !cfg.AutoDisable || forcedEgress || credential.Provider != accountdomain.ProviderBuild || !record.Streaming || record.FirstTokenMS == nil || record.OutputTokens < cfg.MinOutputTokens || !auditRequestSucceeded(record.StatusCode, record.ErrorCode) {
		return nil
	}
	class, tps, _ := audit.ClassifyOutputSpeed(record.OutputTokens, record.ReasoningTokens, *record.FirstTokenMS, record.DurationMS, cfg.SoftTPS, cfg.HardTPS, cfg.MinGenerationMS, cfg.FailClosed)
	if class == "" {
		return nil
	}
	if err := s.selector.disableAccount(ctx, credential); err != nil {
		return err
	}
	s.logger.Info("quality_degraded_disabled", "request_id", record.RequestID, "account_id", credential.ID, "class", class, "output_tps", tps)
	return nil
}

func (s *Service) recordQualityDegraded(ctx context.Context, base audit.Record, credential accountdomain.Credential, usage Usage, startedAt time.Time, trace *infraegress.Trace, provider accountdomain.Provider, attempt *audit.Attempt) {
	record := base
	record.EventID = newAuditEventID()
	accountID := credential.ID
	record.AccountID = &accountID
	record.AccountName = credential.Name
	record.StatusCode = http.StatusOK
	record.ErrorCode = ErrorQualityDegraded
	record.OutputTokens = usage.OutputTokens
	record.ReasoningTokens = usage.ReasoningTokens
	record.TotalTokens = usage.TotalTokens
	record.InputTokens = usage.InputTokens
	if usage.Reported {
		record.UsageSource = audit.UsageSourceUpstream
	}
	record.DurationMS = time.Since(startedAt).Milliseconds()
	record.CreatedAt = time.Now().UTC()
	if attempt != nil {
		single := *attempt
		single.Number = 1
		record.Attempts = []audit.Attempt{single}
	}
	applyAuditEgress(&record, trace, provider)
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalizationTimeout)
	defer cancel()
	if err := s.audits.Create(writeCtx, record); err != nil {
		s.logger.Error("quality_degraded_audit_failed", "event_id", record.EventID, "request_id", record.RequestID, "error", err)
	}
}
