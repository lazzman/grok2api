package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	clientkeydomain "github.com/chenyme/grok2api/backend/internal/domain/clientkey"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	neterrorpkg "github.com/chenyme/grok2api/backend/internal/pkg/neterror"
)

type hedgeResponseParams struct {
	input              Input
	path               string
	route              modeldomain.Route
	operation          audit.Operation
	adapter            provider.ResponseAdapter
	accountScope       clientkeydomain.AccountScope
	quotaMode          string
	affinityKey        string
	reasoningReplayKey string
	selection          *selectionSession
	attemptPolicy      routingAttemptPolicy
	holdCfg            QualityRetryRuntime
	auditBase          *audit.Record
	startedAt          time.Time
	egressTrace        *infraegress.Trace
	failureAttempts    *failureAttemptRecorder
	timing             *generationTiming
	handoffResponse    func(response *provider.Response, lease *accountLease, credential accountdomain.Credential, upstreamStartedAt time.Time, activeTrace *infraegress.Trace) *Result
}

type hedgeBranch struct {
	id                int
	lease             *accountLease
	credential        accountdomain.Credential
	branchCtx         context.Context
	branchCancel      context.CancelFunc
	idempotencyID     string
	stripEncrypted    bool
	transientRetry    int
	startedAt         time.Time
}

type hedgeBranchOutcomeKind string

const (
	hedgeOutcomeDeliver        hedgeBranchOutcomeKind = "deliver"
	hedgeOutcomeWithhold       hedgeBranchOutcomeKind = "withhold"
	hedgeOutcomeTerminalClient hedgeBranchOutcomeKind = "terminal_client"
	hedgeOutcomeRetryableFail  hedgeBranchOutcomeKind = "retryable_fail"
	hedgeOutcomeCanceled       hedgeBranchOutcomeKind = "canceled"
)

type hedgeBranchOutcome struct {
	branch              *hedgeBranch
	kind                hedgeBranchOutcomeKind
	credential          accountdomain.Credential
	response            *provider.Response
	egressTrace         *infraegress.Trace
	usage               Usage
	diagnostic          QualityPeekDiagnostic
	upstreamStartedAt   time.Time
	normalizedEffort    string
	encryptedDowngraded bool
	failure             *UpstreamFailure
	err                 error
	attempts            []audit.Attempt
	retrySameAccount    bool
	fatalStop           bool
	transientRetryBump  bool
}

type hedgeFallback struct {
	response          *provider.Response
	lease             *accountLease
	credential        accountdomain.Credential
	usage             Usage
	diagnostic        QualityPeekDiagnostic
	egressTrace       *infraegress.Trace
	upstreamStartedAt time.Time
}

// createHedgedResponse 以阶梯分时并发调度多个账号：
// 首路在 hedgeDelay 内通过质量闸门时直接交付且不拉起第二路；
// 超出 hedgeDelay 仍未放行时拉起异团队/异出口账号竞速，胜出分支立即交付客户端，
// 其余在飞分支在全局并发额度内转入后台影子质检，直到质量闸门出结论后立刻关流并清理降智号。
func (s *Service) createHedgedResponse(ctx context.Context, p hedgeResponseParams) (*Result, error) {
	maxTotal := p.holdCfg.MaxAttempts
	if !p.attemptPolicy.unlimited && p.attemptPolicy.limit > 0 && p.attemptPolicy.limit < maxTotal {
		maxTotal = p.attemptPolicy.limit
	}
	if maxTotal < 1 {
		maxTotal = 1
	}
	maxConc := p.holdCfg.HedgeMaxConcurrent
	if maxConc > maxTotal {
		maxConc = maxTotal
	}
	if maxConc < 1 {
		maxConc = 1
	}

	excluded := make(map[uint64]bool)
	failureFingerprints := make(map[string]int)
	selection := p.selection
	quotaProbeAttempted := false
	qualityAccountAttempts := 0
	transientRetry := 0
	stripReasoningEncryptedContent := false
	selectionExhausted := false
	nextBranchID := 0

	var lastErr error
	var lastFailure *UpstreamFailure
	var fallback *hedgeFallback
	discardFallback := func(recordDegraded bool) {
		if fallback == nil {
			return
		}
		if recordDegraded {
			upstreamURL := ""
			if fallback.response != nil {
				upstreamURL = fallback.response.UpstreamURL
			}
			attempt := p.failureAttempts.captureQualityDegraded(fallback.credential, fallback.upstreamStartedAt, upstreamURL, fallback.diagnostic)
			s.recordQualityDegraded(ctx, *p.auditBase, fallback.credential, fallback.usage, p.startedAt, fallback.egressTrace, p.route.Provider, &attempt)
		}
		if fallback.response != nil && fallback.response.Body != nil {
			_ = fallback.response.Body.Close()
		}
		fallback = nil
	}

	inFlight := make(map[int]*hedgeBranch, maxConc)
	outcomeCh := make(chan hedgeBranchOutcome, maxTotal+4)
	var lastLaunchAt time.Time

	cancelAndDrainAll := func() {
		for _, branch := range inFlight {
			branch.branchCancel()
		}
		for len(inFlight) > 0 {
			outcome := <-outcomeCh
			delete(inFlight, outcome.branch.id)
			if outcome.response != nil && outcome.response.Body != nil {
				_ = outcome.response.Body.Close()
			}
			outcome.branch.lease.Release()
		}
	}

	launchNext := func() bool {
		for len(inFlight) < maxConc && qualityAccountAttempts < maxTotal && !selectionExhausted {
			selectionStarted := time.Now()
			var err error
			if selection == nil {
				selection, err = s.selector.beginSelectionSessionForKey(ctx, p.route.Provider, p.route.ID, p.route.UpstreamModel, p.quotaMode, p.affinityKey, excluded, !quotaProbeAttempted, p.accountScope)
			}
			var lease *accountLease
			if err == nil {
				if len(inFlight) == 0 {
					lease, err = selection.Acquire(ctx, excluded, !quotaProbeAttempted)
				} else {
					avoidTeams := make(map[string]bool, len(inFlight))
					avoidEgress := make(map[uint64]bool, len(inFlight))
					for _, active := range inFlight {
						if active.credential.TeamID != "" {
							avoidTeams[active.credential.TeamID] = true
						}
						if active.credential.EgressNodeID != 0 {
							avoidEgress[active.credential.EgressNodeID] = true
						}
					}
					lease, err = selection.AcquirePreferringDifferent(ctx, excluded, !quotaProbeAttempted, avoidTeams, avoidEgress)
				}
			}
			p.timing.markSelection(time.Since(selectionStarted))
			if err != nil {
				if len(inFlight) > 0 {
					if !isSelectionUnavailable(err, SelectionSaturated) {
						selectionExhausted = true
					}
					return false
				}
				if lastFailure == nil {
					lastErr = err
				}
				p.failureAttempts.captureSelectionFailure(0, "", err)
				selectionExhausted = true
				return false
			}

			excluded[lease.Credential.ID] = true
			if limited, ok := s.activeTeamModelRateLimit(lease.Credential, p.route.UpstreamModel, time.Now().UTC()); ok {
				lease.Release()
				lastFailure = &UpstreamFailure{
					HTTPStatus: http.StatusTooManyRequests, Code: "upstream_rate_limited", PublicMessage: "上游请求频率受限",
					AccountID: lease.Credential.ID, AccountName: lease.Credential.Name,
					Fingerprint: "429:team_model_rate_limit", RetryAfter: time.Until(limited.Until),
				}
				lastErr = fmt.Errorf("上游 Team 与模型请求频率受限")
				s.logger.Warn("upstream_team_model_rate_limit_active", "request_id", p.input.RequestID, "account_id", lease.Credential.ID, "provider", p.route.Provider, "model", p.route.UpstreamModel, "team_fingerprint", limited.TeamFingerprint, "retry_after", lastFailure.RetryAfter.Round(time.Second))
				continue
			}
			if lease.QuotaProbe {
				quotaProbeAttempted = true
			}
			if lease.QuotaProbeKind == accountdomain.QuotaRecoveryKindPaid {
				recovered, probeErr := s.accounts.ProbePaidQuota(ctx, lease.Credential)
				s.selector.MarkQuotaStateChanged(lease.Credential.Provider, lease.Credential.ID)
				if probeErr != nil || !recovered {
					lease.Release()
					lastErr = firstError(probeErr, fmt.Errorf("付费额度尚未恢复"))
					continue
				}
				lease.QuotaProbe = false
				lease.QuotaProbeKind = ""
				lease.Billing = nil
			}

			nextBranchID++
			qualityAccountAttempts++
			branchCtx, branchCancel := context.WithCancel(context.WithoutCancel(ctx))
			branchIdempotencyID, _ := security.NewOpaqueToken(18)
			branch := &hedgeBranch{
				id:             nextBranchID,
				lease:          lease,
				credential:     lease.Credential,
				branchCtx:      branchCtx,
				branchCancel:   branchCancel,
				idempotencyID:  branchIdempotencyID,
				stripEncrypted: stripReasoningEncryptedContent,
				transientRetry: transientRetry,
				startedAt:      time.Now(),
			}
			inFlight[branch.id] = branch
			lastLaunchAt = branch.startedAt
			if branch.id > 1 {
				s.logger.Info(
					"quality_hedge_launched",
					"request_id", p.input.RequestID,
					"hedge_branch", branch.id,
					"in_flight", len(inFlight),
					"account_id", branch.credential.ID,
					"egress_node_id", branch.credential.EgressNodeID,
				)
			}
			go s.runHedgeBranch(branch, p, outcomeCh)
			return true
		}
		return false
	}

	var hedgeTimer *time.Timer
	stopHedgeTimer := func() {
		if hedgeTimer == nil {
			return
		}
		if !hedgeTimer.Stop() {
			select {
			case <-hedgeTimer.C:
			default:
			}
		}
		hedgeTimer = nil
	}
	defer stopHedgeTimer()

	// 启动首路分支。
	launchNext()

	for len(inFlight) > 0 {
		// 若还有并发名额与候选预算，计算下一次分时拉起时间。
		stopHedgeTimer()
		var hedgeTimerCh <-chan time.Time
		if len(inFlight) < maxConc && qualityAccountAttempts < maxTotal && !selectionExhausted {
			wait := p.holdCfg.HedgeDelay - time.Since(lastLaunchAt)
			if wait <= 0 {
				if launchNext() {
					continue
				}
			} else {
				hedgeTimer = time.NewTimer(wait)
				hedgeTimerCh = hedgeTimer.C
			}
		}

		select {
		case <-ctx.Done():
			stopHedgeTimer()
			cancelAndDrainAll()
			discardFallback(true)
			lastErr = ctx.Err()
			lastFailure = &UpstreamFailure{
				HTTPStatus: 499, Code: "request_canceled", PublicMessage: "请求已取消", Cause: ctx.Err(),
			}
			goto finalizeFailure

		case <-hedgeTimerCh:
			hedgeTimer = nil
			launchNext()

		case outcome := <-outcomeCh:
			delete(inFlight, outcome.branch.id)
			if outcome.encryptedDowngraded {
				stripReasoningEncryptedContent = true
			}
			if outcome.kind != hedgeOutcomeCanceled && len(outcome.attempts) > 0 {
				p.failureAttempts.appendAll(outcome.attempts)
			}

			switch outcome.kind {
			case hedgeOutcomeDeliver:
				stopHedgeTimer()
				outcome.branch.branchCancel()
				discardFallback(true)
				if outcome.normalizedEffort != "" {
					p.auditBase.ReasoningEffort = outcome.normalizedEffort
				}
				if selection != nil && selection.stickyKey != "" && s.selector.sticky != nil {
					stickyTTL, _, _, _ := s.selector.routingConfig()
					_ = s.selector.sticky.Set(ctx, selection.stickyKey, outcome.credential.ID, time.Now().UTC().Add(stickyTTL))
				}
				if len(inFlight) > 0 {
					s.spawnHedgeShadowReaper(inFlight, outcomeCh, p, *p.auditBase)
				}
				return p.handoffResponse(outcome.response, outcome.branch.lease, outcome.credential, outcome.upstreamStartedAt, outcome.egressTrace), nil

			case hedgeOutcomeTerminalClient:
				stopHedgeTimer()
				outcome.branch.branchCancel()
				cancelAndDrainAll()
				discardFallback(true)
				if outcome.normalizedEffort != "" {
					p.auditBase.ReasoningEffort = outcome.normalizedEffort
				}
				return p.handoffResponse(outcome.response, outcome.branch.lease, outcome.credential, outcome.upstreamStartedAt, outcome.egressTrace), nil

			case hedgeOutcomeWithhold:
				outcome.branch.branchCancel()
				s.applyMissingThinkingPenalty(ctx, p.input.RequestID, outcome.credential, p.holdCfg.AccountCooldown, p.holdCfg.AutoDisable)
				hasMore := len(inFlight) > 0 || (qualityAccountAttempts < maxTotal && !selectionExhausted && selection != nil && selection.hasAvailableCandidate(excluded, !quotaProbeAttempted))
				if !hasMore && p.holdCfg.OnExhausted == qualityRetryFailOpen {
					stopHedgeTimer()
					discardFallback(true)
					if outcome.normalizedEffort != "" {
						p.auditBase.ReasoningEffort = outcome.normalizedEffort
					}
					s.logger.Info("quality_degraded_deliver_last", append([]any{"request_id", p.input.RequestID, "account_id", outcome.credential.ID, "quality_attempt", qualityAccountAttempts, "usage_output_tokens", outcome.usage.OutputTokens}, qualityDiagnosticLogAttrs(outcome.diagnostic)...)...)
					return p.handoffResponse(outcome.response, outcome.branch.lease, outcome.credential, outcome.upstreamStartedAt, outcome.egressTrace), nil
				}
				if hasMore && p.holdCfg.OnExhausted == qualityRetryFailOpen {
					discardFallback(true)
					fallback = &hedgeFallback{
						response:          outcome.response,
						lease:             outcome.branch.lease,
						credential:        outcome.credential,
						usage:             outcome.usage,
						diagnostic:        outcome.diagnostic,
						egressTrace:       outcome.egressTrace,
						upstreamStartedAt: outcome.upstreamStartedAt,
					}
					outcome.branch.lease.completeSelectorObservation(true)
					outcome.branch.lease.Release()
				} else {
					upstreamURL := ""
					if outcome.response != nil {
						upstreamURL = outcome.response.UpstreamURL
					}
					attempt := p.failureAttempts.captureQualityDegraded(outcome.credential, outcome.upstreamStartedAt, upstreamURL, outcome.diagnostic)
					s.recordQualityDegraded(ctx, *p.auditBase, outcome.credential, outcome.usage, p.startedAt, outcome.egressTrace, p.route.Provider, &attempt)
					if outcome.response != nil && outcome.response.Body != nil {
						_ = outcome.response.Body.Close()
					}
					outcome.branch.lease.Release()
				}
				lastErr = errQualityDegraded
				lastFailure = &UpstreamFailure{
					HTTPStatus: http.StatusServiceUnavailable, Code: ErrorQualityDegraded,
					PublicMessage: "上游响应缺少推理", AccountID: outcome.credential.ID, AccountName: outcome.credential.Name,
					Cause: errQualityDegraded,
				}
				if hasMore {
					s.logger.Info("quality_degraded_retry", append([]any{"request_id", p.input.RequestID, "account_id", outcome.credential.ID, "quality_attempt", qualityAccountAttempts, "usage_output_tokens", outcome.usage.OutputTokens}, qualityDiagnosticLogAttrs(outcome.diagnostic)...)...)
				} else {
					s.logger.Info("quality_degraded_rejected", append([]any{"request_id", p.input.RequestID, "account_id", outcome.credential.ID, "quality_attempt", qualityAccountAttempts, "usage_output_tokens", outcome.usage.OutputTokens}, qualityDiagnosticLogAttrs(outcome.diagnostic)...)...)
				}

			case hedgeOutcomeRetryableFail:
				outcome.branch.branchCancel()
				if outcome.err != nil {
					lastErr = outcome.err
				}
				if outcome.failure != nil {
					lastFailure = outcome.failure
				}
				if outcome.retrySameAccount && selection != nil {
					delete(excluded, outcome.credential.ID)
					selection.RetryAccount(outcome.credential.ID)
				}
				if outcome.transientRetryBump {
					transientRetry++
				}
				if outcome.fatalStop || (outcome.failure != nil && shouldStopForNonAccountFingerprint(failureFingerprints, outcome.failure)) {
					selectionExhausted = true
				}

			case hedgeOutcomeCanceled:
				outcome.branch.branchCancel()
			}

			// 若当前在飞数归零且仍有预算，立即补位下一路，不白等 hedgeDelay。
			if len(inFlight) == 0 && !selectionExhausted && qualityAccountAttempts < maxTotal {
				launchNext()
			}
		}
	}

	if fallback != nil {
		if ctx.Err() == nil && p.holdCfg.OnExhausted == qualityRetryFailOpen {
			selected := fallback
			fallback = nil
			s.logger.Info("quality_degraded_fallback", append([]any{"request_id", p.input.RequestID, "account_id", selected.credential.ID, "quality_attempts", qualityAccountAttempts}, qualityDiagnosticLogAttrs(selected.diagnostic)...)...)
			return p.handoffResponse(selected.response, selected.lease, selected.credential, selected.upstreamStartedAt, selected.egressTrace), nil
		}
		discardFallback(true)
	}

finalizeFailure:
	if lastFailure != nil {
		record := *p.auditBase
		record.StatusCode = lastFailure.HTTPStatus
		record.DurationMS = time.Since(p.startedAt).Milliseconds()
		record.ErrorCode = lastFailure.AuditCode()
		record.Attempts = p.failureAttempts.snapshot()
		record.CreatedAt = time.Now().UTC()
		applyAuditEgress(&record, p.egressTrace, p.route.Provider)
		if lastFailure.AccountID != 0 {
			accountID := lastFailure.AccountID
			record.AccountID = &accountID
			record.AccountName = lastFailure.AccountName
		}
		persistCtx, cancel := context.WithTimeout(context.Background(), finalizationTimeout)
		defer cancel()
		if err := s.audits.Create(persistCtx, record); err != nil {
			s.logger.Error("request_usage_write_failed", "event_id", record.EventID, "request_id", p.input.RequestID, "error", err)
		}
		return nil, lastFailure
	}
	if lastErr == nil {
		lastErr = ErrNoAvailableAccount
	}
	record := *p.auditBase
	record.StatusCode = http.StatusServiceUnavailable
	record.DurationMS = time.Since(p.startedAt).Milliseconds()
	record.ErrorCode = "upstream_unavailable"
	var selectionFailure *SelectionUnavailableError
	if errors.As(lastErr, &selectionFailure) {
		record.StatusCode = selectionFailure.HTTPStatus()
		record.ErrorCode = selectionFailure.Code()
		if selectionFailure.AccountID != 0 {
			accountID := selectionFailure.AccountID
			record.AccountID = &accountID
			record.AccountName = selectionFailure.AccountName
		}
	}
	record.Attempts = p.failureAttempts.snapshot()
	record.CreatedAt = time.Now().UTC()
	applyAuditEgress(&record, p.egressTrace, p.route.Provider)
	persistCtx, cancel := context.WithTimeout(context.Background(), finalizationTimeout)
	defer cancel()
	if err := s.audits.Create(persistCtx, record); err != nil {
		s.logger.Error("request_usage_write_failed", "event_id", record.EventID, "request_id", p.input.RequestID, "error", err)
	}
	return nil, fmt.Errorf("%w: %w", ErrNoAvailableAccount, lastErr)
}

func (s *Service) runHedgeBranch(branch *hedgeBranch, p hedgeResponseParams, outcomeCh chan<- hedgeBranchOutcome) {
	branchTraceCtx, branchTrace := infraegress.WithTrace(branch.branchCtx)
	physicalCallCtx := infraegress.WithPhysicalCallTrace(branchTraceCtx, string(p.route.Provider), string(p.operation))
	branchAttempts := newFailureAttemptRecorder(http.MethodPost, p.path)
	branchMeta := &provider.NormalizedRequestMetadata{}

	credential := branch.credential
	encryptedDowngraded := false
	upstreamStartedAt := branch.startedAt

	forward := func(cred accountdomain.Credential) (*provider.Response, error) {
		started := time.Now()
		upstreamStartedAt = started
		branch.lease.markSelectorUpstreamStarted()
		resp, err := p.adapter.ForwardResponse(physicalCallCtx, provider.ResponseResourceRequest{
			Credential:                     cred,
			Billing:                        branch.lease.Billing,
			Method:                         http.MethodPost,
			Path:                           p.path,
			Model:                          p.route.UpstreamModel,
			PromptCacheKey:                 p.input.PromptCacheKey,
			ReasoningReplayKey:             p.reasoningReplayKey,
			StripReasoningEncryptedContent: branch.stripEncrypted,
			AllowClientToolCacheRoute:      p.input.AllowClientToolCacheRoute,
			GrokTurnIndex:                  p.input.GrokTurnIndex,
			TransientRetry:                 branch.transientRetry,
			IdempotencyID:                  branch.idempotencyID,
			Body:                           p.input.Body,
			Streaming:                      p.input.Streaming,
			NormalizeBody:                  true,
			Operation:                      string(p.operation),
			NormalizedMetadata:             branchMeta,
		})
		if resp != nil && resp.ReasoningEncryptedContentDowngraded {
			encryptedDowngraded = true
		}
		err = branchAttempts.captureResponse(cred, started, resp, err)
		return resp, err
	}

	ensure := func(cred accountdomain.Credential, force bool) (accountdomain.Credential, error) {
		started := time.Now()
		res, err := s.accounts.EnsureCredential(branch.branchCtx, cred, force)
		branchAttempts.captureCredentialFailure(cred, started, force, err)
		return res, err
	}

	send := func(outcome hedgeBranchOutcome) {
		outcome.branch = branch
		outcome.credential = credential
		outcome.egressTrace = branchTrace
		outcome.upstreamStartedAt = upstreamStartedAt
		outcome.normalizedEffort = branchMeta.ReasoningEffort
		outcome.encryptedDowngraded = encryptedDowngraded
		outcome.attempts = branchAttempts.snapshot()
		outcomeCh <- outcome
	}

	ensured, err := ensure(credential, false)
	if err != nil {
		branch.lease.Release()
		if branch.branchCtx.Err() != nil || errors.Is(err, context.Canceled) {
			send(hedgeBranchOutcome{kind: hedgeOutcomeCanceled, err: err})
			return
		}
		send(hedgeBranchOutcome{
			kind:    hedgeOutcomeRetryableFail,
			err:     err,
			failure: newCredentialUpstreamFailure(err, credential.ID, credential.Name),
		})
		return
	}
	credential = ensured

	response, err := forward(credential)
	if err != nil {
		branch.lease.Release()
		if branch.branchCtx.Err() != nil || errors.Is(err, context.Canceled) {
			send(hedgeBranchOutcome{kind: hedgeOutcomeCanceled, err: err})
			return
		}
		if isSSOCredentialRejected(err, credential) {
			s.markSSOCredentialRejected(context.Background(), credential, fmt.Sprintf("%s SSO credential rejected", credential.Provider))
			send(hedgeBranchOutcome{
				kind:    hedgeOutcomeRetryableFail,
				err:     err,
				failure: newHTTPUpstreamFailure(http.StatusUnauthorized, nil, credential.ID, credential.Name),
			})
			return
		}
		failure := newTransportUpstreamFailure(err, credential.ID, credential.Name)
		if !isRetryableTransportFailure(credential.Provider, err) {
			send(hedgeBranchOutcome{kind: hedgeOutcomeRetryableFail, err: err, failure: failure, fatalStop: true})
			return
		}
		if status, retryAfter, classified := upstreamResponseErrorHealthPenalty(err, p.holdCfg.IdleAccountCooldown); classified {
			writeCtx, writeCancel := context.WithTimeout(context.Background(), finalizationTimeout)
			_ = s.selector.MarkFailureAfterSuccess(writeCtx, credential, status, retryAfter)
			writeCancel()
		} else {
			s.selector.MarkFailure(context.Background(), credential, 0, 0)
		}
		send(hedgeBranchOutcome{
			kind:               hedgeOutcomeRetryableFail,
			err:                err,
			failure:            failure,
			transientRetryBump: isBuildTransientRetryError(err),
		})
		return
	}

	authRefreshed := false
handleHedgeResponse:
	if response.ModelCatalogChanged {
		s.queueAccountModelSync(credential.ID)
	}
	if response.StatusCode == http.StatusUnauthorized {
		_ = response.Body.Close()
		if credential.AuthType == accountdomain.AuthTypeSSO {
			s.markSSOCredentialRejected(context.Background(), credential, fmt.Sprintf("%s SSO credential rejected", credential.Provider))
			branch.lease.Release()
			send(hedgeBranchOutcome{
				kind:    hedgeOutcomeRetryableFail,
				err:     fmt.Errorf("%s SSO 凭据已失效", credential.Provider),
				failure: newHTTPUpstreamFailure(http.StatusUnauthorized, nil, credential.ID, credential.Name),
			})
			return
		}
		if s.markPermanentlyUnrefreshableCredentialRejected(context.Background(), credential) {
			branch.lease.Release()
			send(hedgeBranchOutcome{
				kind:    hedgeOutcomeRetryableFail,
				err:     accountapp.ErrCredentialRefreshPermanent,
				failure: newHTTPUpstreamFailure(http.StatusUnauthorized, nil, credential.ID, credential.Name),
			})
			return
		}
		authRefreshed = true
		refreshed, refreshErr := ensure(credential, true)
		if refreshErr == nil {
			credential = refreshed
			response, err = forward(refreshed)
		}
		if refreshErr != nil || err != nil {
			if errors.Is(refreshErr, accountapp.ErrCredentialRefreshPermanent) {
				s.markCredentialRejectedAfterPermanentRefresh(context.Background(), credential)
			}
			branch.lease.Release()
			if branch.branchCtx.Err() != nil || errors.Is(err, context.Canceled) {
				send(hedgeBranchOutcome{kind: hedgeOutcomeCanceled, err: firstError(refreshErr, err)})
				return
			}
			if refreshErr != nil {
				send(hedgeBranchOutcome{
					kind:    hedgeOutcomeRetryableFail,
					err:     refreshErr,
					failure: newCredentialUpstreamFailure(refreshErr, credential.ID, credential.Name),
				})
				return
			}
			failure := newTransportUpstreamFailure(err, credential.ID, credential.Name)
			send(hedgeBranchOutcome{
				kind:               hedgeOutcomeRetryableFail,
				err:                err,
				failure:            failure,
				fatalStop:          !isRetryableTransportFailure(credential.Provider, err),
				transientRetryBump: isBuildTransientRetryError(err),
			})
			return
		}
		if response.StatusCode == http.StatusUnauthorized {
			body, _ := readRetryableBody(response.Body)
			_ = s.accounts.MarkReauthRequired(context.Background(), credential.ID, "Grok Build OAuth credential rejected after refresh")
			s.selector.MarkQuotaStateChanged(credential.Provider, credential.ID)
			branch.lease.Release()
			send(hedgeBranchOutcome{
				kind:    hedgeOutcomeRetryableFail,
				err:     fmt.Errorf("刷新后上游仍返回 401"),
				failure: newHTTPUpstreamFailure(http.StatusUnauthorized, body, credential.ID, credential.Name),
			})
			return
		}
	}

	egressForbidden := s.providers.RetryForbiddenAsEgress(credential.Provider) && response.StatusCode == http.StatusForbidden
	var httpFailure *UpstreamFailure
	if response.StatusCode == http.StatusForbidden {
		retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())
		body, _ := readRetryableBody(response.Body)
		httpFailure = newHTTPUpstreamFailure(response.StatusCode, body, credential.ID, credential.Name)
		if isTerminalRequestForbidden(credential.Provider, httpFailure) {
			response.Body = io.NopCloser(bytes.NewReader(body))
			send(hedgeBranchOutcome{kind: hedgeOutcomeTerminalClient, response: response, failure: httpFailure})
			return
		}
		if httpFailure.AccountBlocked || isConsoleNoCreditsFailure(credential.Provider, httpFailure) {
			reason := fmt.Sprintf("%s account is blocked", credential.Provider)
			if !httpFailure.AccountBlocked {
				reason = consoleNoCreditsReason
			}
			handled := s.markReauthRequired(context.Background(), p.input.RequestID, credential, reason)
			if httpFailure.AccountScoped && !handled {
				s.selector.MarkFailure(context.Background(), credential, response.StatusCode, retryAfter)
			}
			branch.lease.Release()
			send(hedgeBranchOutcome{kind: hedgeOutcomeRetryableFail, err: fmt.Errorf("上游返回 %d", response.StatusCode), failure: httpFailure})
			return
		}
		if egressForbidden {
			branch.lease.Release()
			send(hedgeBranchOutcome{kind: hedgeOutcomeRetryableFail, err: fmt.Errorf("上游出口会话被拒绝"), failure: httpFailure, retrySameAccount: true})
			return
		}
		response.Body = io.NopCloser(bytes.NewReader(body))
	}

	if isRetryableResponse(response, p.route.Provider) {
		retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())
		body, _ := readRetryableBody(response.Body)
		httpFailure = newHTTPUpstreamFailure(response.StatusCode, body, credential.ID, credential.Name)
		if response.StatusCode == http.StatusTooManyRequests && response.RateLimit == nil {
			if metadata := provider.ParseRateLimitMetadata(body); metadata != nil {
				response.RateLimit = metadata
				if retryAfter <= 0 && metadata.RetryAfter > 0 {
					retryAfter = metadata.RetryAfter
				}
			}
		}
		buildForbiddenReauth := credential.Provider == accountdomain.ProviderBuild && s.shouldInvalidateBuildForbidden(httpFailure)
		if response.StatusCode == http.StatusTooManyRequests && response.RateLimit != nil && response.RateLimit.Model == p.route.UpstreamModel {
			rateLimitMeta := *response.RateLimit
			if strings.TrimSpace(rateLimitMeta.TeamID) == "" {
				rateLimitMeta.TeamID = strings.TrimSpace(credential.TeamID)
			}
			if rateLimitMeta.TeamID != "" {
				limited := s.markTeamModelRateLimit(credential, p.route.UpstreamModel, rateLimitMeta, time.Now().UTC())
				httpFailure.AccountScoped = false
				httpFailure.Fingerprint = "429:team_model_rate_limit"
				httpFailure.RetryAfter = time.Until(limited.Until)
				branch.lease.Release()
				s.logger.Warn("upstream_team_model_rate_limited", "request_id", p.input.RequestID, "provider", credential.Provider, "model", p.route.UpstreamModel, "team_fingerprint", limited.TeamFingerprint, "scope", rateLimitMeta.Scope, "actual", rateLimitMeta.Actual, "limit", rateLimitMeta.Limit, "retry_after", httpFailure.RetryAfter)
				send(hedgeBranchOutcome{
					kind:    hedgeOutcomeRetryableFail,
					err:     fmt.Errorf("上游 Team 与模型请求频率受限"),
					failure: httpFailure,
				})
				return
			}
		}
		if credential.Provider != accountdomain.ProviderBuild && s.providers.SupportsCredentialRefresh(credential.Provider) && !authRefreshed && credential.EncryptedRefreshToken != "" && !httpFailure.AccountBlocked && !buildForbiddenReauth && (httpFailure.PermanentAccountDenial || httpFailure.CredentialRejected) {
			authRefreshed = true
			refreshed, refreshErr := ensure(credential, true)
			if refreshErr == nil {
				credential = refreshed
				response, err = forward(refreshed)
				if err == nil {
					goto handleHedgeResponse
				}
			}
			branch.lease.Release()
			if branch.branchCtx.Err() != nil || errors.Is(err, context.Canceled) {
				send(hedgeBranchOutcome{kind: hedgeOutcomeCanceled, err: firstError(refreshErr, err)})
				return
			}
			if refreshErr != nil {
				send(hedgeBranchOutcome{kind: hedgeOutcomeRetryableFail, err: refreshErr, failure: newCredentialUpstreamFailure(refreshErr, credential.ID, credential.Name)})
				return
			}
			send(hedgeBranchOutcome{kind: hedgeOutcomeRetryableFail, err: err, failure: newTransportUpstreamFailure(err, credential.ID, credential.Name), transientRetryBump: isBuildTransientRetryError(err)})
			return
		}
		bgCtx := context.Background()
		failureHandled := false
		if branch.lease.QuotaMode != "" && (response.StatusCode == http.StatusTooManyRequests || credential.Provider == accountdomain.ProviderConsole && response.StatusCode == http.StatusPaymentRequired) {
			state, reconcileErr := s.accounts.ReconcileRateLimit(bgCtx, credential.ID, branch.lease.QuotaMode, retryAfter)
			s.applyRateLimitReconciliation(bgCtx, credential, response.StatusCode, retryAfter, state, reconcileErr)
			failureHandled = true
		} else if used, limit, exhausted := parseFreeQuotaExhaustion(body); exhausted {
			s.selector.MarkFreeQuotaExhausted(bgCtx, credential, used, limit)
			failureHandled = true
		} else if httpFailure.ModelQuotaExhausted {
			s.selector.MarkModelQuotaExhausted(bgCtx, credential, branch.lease.Billing, p.route.UpstreamModel, retryAfter)
			failureHandled = true
		} else if httpFailure.FreeQuotaExhausted {
			s.selector.MarkFreeQuotaExhausted(bgCtx, credential, 0, 0)
			failureHandled = true
		} else if httpFailure.SpendingLimitBlocked || httpFailure.QuotaExhausted {
			if err := s.selector.MarkPaymentQuotaExhausted(bgCtx, credential, quotaRecoveryHints{Billing: branch.lease.Billing}); err == nil {
				failureHandled = true
			}
		}
		if httpFailure.AccountBlocked {
			failureHandled = s.markReauthRequired(bgCtx, p.input.RequestID, credential, fmt.Sprintf("%s account is blocked", credential.Provider))
		} else if buildForbiddenReauth {
			failureHandled = s.markReauthRequired(bgCtx, p.input.RequestID, credential, fmt.Sprintf("%s upstream error code %s matched the invalidation policy", credential.Provider, httpFailure.UpstreamCode))
		} else if s.providers.SupportsCredentialRefresh(credential.Provider) && httpFailure.PermanentAccountDenial {
			if credential.Provider == accountdomain.ProviderBuild {
				if modelErr := s.selector.MarkModelAccessDenied(bgCtx, credential, p.route.UpstreamModel, retryAfter); modelErr == nil {
					failureHandled = true
				}
				if s.markBuildChatDeniedAsReauth.Load() {
					reauthHandled := s.markReauthRequired(bgCtx, p.input.RequestID, credential, fmt.Sprintf("%s chat endpoint access denied", credential.Provider))
					failureHandled = failureHandled || reauthHandled
				}
			} else {
				failureHandled = s.markReauthRequired(bgCtx, p.input.RequestID, credential, fmt.Sprintf("%s chat endpoint access denied", credential.Provider))
			}
		} else if s.providers.SupportsCredentialRefresh(credential.Provider) && httpFailure.CredentialRejected {
			failureHandled = s.markReauthRequired(bgCtx, p.input.RequestID, credential, fmt.Sprintf("%s credential rejected", credential.Provider))
		}
		if !failureHandled && (httpFailure.AccountScoped || credential.Provider == accountdomain.ProviderBuild && response.StatusCode == http.StatusForbidden) {
			s.selector.MarkFailure(bgCtx, credential, response.StatusCode, retryAfter)
		} else if !httpFailure.AccountScoped && response.StatusCode >= http.StatusInternalServerError {
			_ = s.selector.markSoftFailure(bgCtx, credential, response.StatusCode, retryAfter)
		}
		branch.lease.Release()
		send(hedgeBranchOutcome{
			kind:               hedgeOutcomeRetryableFail,
			err:                fmt.Errorf("上游返回 %d", response.StatusCode),
			failure:            httpFailure,
			transientRetryBump: isBuildTransientRetryStatus(response.StatusCode),
		})
		return
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		send(hedgeBranchOutcome{kind: hedgeOutcomeTerminalClient, response: response})
		return
	}

	s.selector.markSuccess(context.Background(), credential, branch.lease.QuotaProbe)
	replay, verdict, peekUsage, _, peekDiag, peekErr := peekQualityStreamWithDiagnostic(branch.branchCtx, response.Body, qualityProtocolForOperation(p.operation), p.holdCfg)
	if peekErr != nil {
		if replay != nil {
			_ = replay.Close()
		} else if response.Body != nil {
			_ = response.Body.Close()
		}
		branch.lease.Release()
		if branch.branchCtx.Err() != nil || errors.Is(peekErr, context.Canceled) {
			send(hedgeBranchOutcome{kind: hedgeOutcomeCanceled, err: peekErr})
			return
		}
		failure := newTransportUpstreamFailure(peekErr, credential.ID, credential.Name)
		if neterrorpkg.IsUpstreamStreamIdleTimeout(peekErr) || errors.Is(peekErr, errQualityEmptyStream) {
			writeCtx, writeCancel := context.WithTimeout(context.Background(), finalizationTimeout)
			_ = s.selector.MarkFailureAfterSuccess(writeCtx, credential, http.StatusGatewayTimeout, p.holdCfg.IdleAccountCooldown)
			writeCancel()
		}
		send(hedgeBranchOutcome{
			kind:               hedgeOutcomeRetryableFail,
			err:                peekErr,
			failure:            failure,
			transientRetryBump: isBuildTransientRetryError(peekErr),
		})
		return
	}
	response.Body = replay

	if verdict == QualityDeliver {
		if diagnostic := response.RecoveredPrimaryFailure; diagnostic != nil {
			recoveredFailure := newHTTPUpstreamFailure(diagnostic.StatusCode, diagnostic.Body, credential.ID, credential.Name)
			if recoveredFailure.AccountBlocked || (credential.Provider == accountdomain.ProviderBuild && s.shouldInvalidateBuildForbidden(recoveredFailure)) {
				reason := fmt.Sprintf("%s primary endpoint denied account access", credential.Provider)
				if !s.markReauthRequired(context.Background(), p.input.RequestID, credential, reason) {
					s.selector.MarkModelAccessDenied(context.Background(), credential, p.route.UpstreamModel, 0)
				}
			}
		}
		send(hedgeBranchOutcome{
			kind:       hedgeOutcomeDeliver,
			response:   response,
			usage:      peekUsage,
			diagnostic: peekDiag,
		})
		return
	}

	send(hedgeBranchOutcome{
		kind:       hedgeOutcomeWithhold,
		response:   response,
		usage:      peekUsage,
		diagnostic: peekDiag,
	})
}

// spawnHedgeShadowReaper 接管竞速胜出后仍在飞的其余分支：
// 若全局影子质检并发池有余量，则让其在剩余 holdTimeout 内跑完质量闸门窥探；
// 出思考明文即证明账号健康并静默关闭释放，命中降智则自动惩罚并写质量审计；
// 若全局影子额度已满则立刻取消且不惩罚账号。
func (s *Service) spawnHedgeShadowReaper(
	remaining map[int]*hedgeBranch,
	outcomeCh <-chan hedgeBranchOutcome,
	p hedgeResponseParams,
	auditBaseSnapshot audit.Record,
) {
	branches := make(map[int]*hedgeBranch, len(remaining))
	slotHeld := make(map[int]bool, len(remaining))
	deadlines := make(map[int]time.Time, len(remaining))
	for id, branch := range remaining {
		branches[id] = branch
		if s.tryAcquireShadowQualitySlot() {
			slotHeld[id] = true
			deadlines[id] = branch.startedAt.Add(p.holdCfg.HoldTimeout + 2*time.Second)
		} else {
			branch.branchCancel()
		}
	}

	s.shadowQualityWG.Add(1)
	go func() {
		defer s.shadowQualityWG.Done()
		bgCtx := context.Background()
		for len(branches) > 0 {
			var nextDeadline time.Time
			var nextDeadlineID int
			for id, dl := range deadlines {
				if nextDeadline.IsZero() || dl.Before(nextDeadline) {
					nextDeadline = dl
					nextDeadlineID = id
				}
			}
			var timer *time.Timer
			var timerCh <-chan time.Time
			if !nextDeadline.IsZero() {
				wait := time.Until(nextDeadline)
				if wait < 0 {
					wait = 0
				}
				timer = time.NewTimer(wait)
				timerCh = timer.C
			}

			select {
			case <-timerCh:
				if branch, ok := branches[nextDeadlineID]; ok {
					branch.branchCancel()
				}
				delete(deadlines, nextDeadlineID)

			case outcome := <-outcomeCh:
				if timer != nil {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
				}
				id := outcome.branch.id
				delete(branches, id)
				delete(deadlines, id)
				outcome.branch.branchCancel()
				if slotHeld[id] {
					delete(slotHeld, id)
					s.releaseShadowQualitySlot()
				}

				switch outcome.kind {
				case hedgeOutcomeDeliver:
					if outcome.response != nil && outcome.response.Body != nil {
						_ = outcome.response.Body.Close()
					}
					outcome.branch.lease.completeSelectorObservation(true)
					outcome.branch.lease.Release()
					s.logger.Info(
						"quality_hedge_shadow_healthy",
						"request_id", p.input.RequestID,
						"account_id", outcome.credential.ID,
						"hedge_shadow", true,
						"has_reasoning_delta", outcome.diagnostic.Signals.HasReasoningDelta,
						"has_tool_call", outcome.diagnostic.Signals.HasToolCall,
					)

				case hedgeOutcomeWithhold:
					upstreamURL := ""
					if outcome.response != nil {
						upstreamURL = outcome.response.UpstreamURL
						if outcome.response.Body != nil {
							_ = outcome.response.Body.Close()
						}
					}
					outcome.branch.lease.Release()
					s.applyMissingThinkingPenalty(bgCtx, p.input.RequestID, outcome.credential, p.holdCfg.AccountCooldown, p.holdCfg.AutoDisable)
					shadowRecorder := newFailureAttemptRecorder(http.MethodPost, p.path)
					attempt := shadowRecorder.captureQualityDegraded(outcome.credential, outcome.upstreamStartedAt, upstreamURL, outcome.diagnostic)
					s.recordQualityDegraded(bgCtx, auditBaseSnapshot, outcome.credential, outcome.usage, p.startedAt, outcome.egressTrace, p.route.Provider, &attempt)
					s.logger.Info(
						"quality_hedge_shadow_degraded",
						append([]any{
							"request_id", p.input.RequestID,
							"account_id", outcome.credential.ID,
							"hedge_shadow", true,
							"usage_output_tokens", outcome.usage.OutputTokens,
						}, qualityDiagnosticLogAttrs(outcome.diagnostic)...)...,
					)

				case hedgeOutcomeTerminalClient:
					if outcome.response != nil && outcome.response.Body != nil {
						_ = outcome.response.Body.Close()
					}
					outcome.branch.lease.Release()

				case hedgeOutcomeRetryableFail, hedgeOutcomeCanceled:
					if outcome.response != nil && outcome.response.Body != nil {
						_ = outcome.response.Body.Close()
					}
					outcome.branch.lease.Release()
				}
			}
		}
	}()
}
