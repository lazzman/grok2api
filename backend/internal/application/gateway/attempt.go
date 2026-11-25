package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	neterrorpkg "github.com/chenyme/grok2api/backend/internal/pkg/neterror"
)

const (
	attemptStageQualityHold         = "quality_hold"
	attemptStageQualityPeekError    = "quality_peek_error"
	attemptStageHedgeShadowPrefix   = "hedge_shadow:"
	attemptStageHedgeShadowHealthy  = "hedge_shadow_healthy"
	attemptStageHedgeShadowDegraded = "hedge_shadow_degraded"
	attemptStageHedgeShadowPeekErr  = "hedge_shadow_peek_error"
	attemptStageHedgeShadowCanceled = "hedge_shadow_canceled"
	attemptStageHedgeShadowFailed   = "hedge_shadow_failed"
	attemptStageMaxLen              = 64
)

type failureAttemptRecorder struct {
	mu                  sync.Mutex
	method              string
	path                string
	hedgeBranch         int
	remainingBodyBudget int
	attempts            []audit.Attempt
	sealed              bool
	commitDone          chan struct{}
	commitDoneOnce      sync.Once
	commitOK            bool
}

func newFailureAttemptRecorder(method, path string) *failureAttemptRecorder {
	return newHedgeFailureAttemptRecorder(method, path, 0)
}

func newHedgeFailureAttemptRecorder(method, path string, hedgeBranch int) *failureAttemptRecorder {
	return &failureAttemptRecorder{
		method:              method,
		path:                sanitizeRequestPath(path),
		hedgeBranch:         max(0, hedgeBranch),
		remainingBodyBudget: diagnosticTotalBodyLimit,
		commitDone:          make(chan struct{}),
	}
}

const (
	diagnosticBodyLimit        = 64 << 10
	diagnosticTotalBodyLimit   = 256 << 10
	diagnosticTextLimit        = 2048
	diagnosticHeadersLimit     = 4 << 10
	diagnosticHeaderValueLimit = 512
	diagnosticErrorFrameLimit  = 8
)

var (
	diagnosticAuthorizationPattern = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	diagnosticCookiePattern        = regexp.MustCompile(`(?i)\b(cookie|set-cookie)\b\s*[:=]\s*[^\r\n]+`)
	diagnosticSecretPattern        = regexp.MustCompile(`(?i)(["']?(?:authorization|proxy-authorization|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)["']?\s*[:=]\s*["']?)[^"'\s,;}]+`)
	diagnosticOpaqueFieldPattern   = regexp.MustCompile(`(?i)(["'](?:encrypted[_-]?content|compaction[_-]?(?:blob|state)|opaque[_-]?(?:state|data))["']\s*[:=]\s*["'])((?:\\.|[^"'\\])*)(["']|$)`)
	diagnosticURLPattern           = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

func (r *failureAttemptRecorder) captureCredentialFailure(credential accountdomain.Credential, startedAt time.Time, force bool, err error) {
	if err == nil {
		return
	}
	stage := "credential_validation"
	if force {
		stage = "credential_refresh"
	}
	r.append(audit.Attempt{
		Source:         audit.AttemptSourceCredential,
		Stage:          stage,
		AccountID:      auditAccountID(credential.ID),
		AccountName:    credential.Name,
		StartedAt:      startedAt.UTC(),
		DurationMS:     time.Since(startedAt).Milliseconds(),
		TransportError: sanitizeDiagnosticText(err.Error(), diagnosticTextLimit),
		ErrorChain:     errorFrames(err),
	})
}

func (r *failureAttemptRecorder) captureResponse(credential accountdomain.Credential, startedAt time.Time, response *provider.Response, requestErr error) error {
	if response != nil {
		r.captureRecoveredAttempts(credential, startedAt, response)
	}
	if requestErr != nil {
		r.append(audit.Attempt{
			Source:         audit.AttemptSourceTransport,
			Stage:          transportStage(requestErr),
			AccountID:      auditAccountID(credential.ID),
			AccountName:    credential.Name,
			Method:         r.method,
			RequestPath:    r.path,
			UpstreamURL:    sanitizeUpstreamURL(errorUpstreamURL(requestErr)),
			StartedAt:      startedAt.UTC(),
			DurationMS:     time.Since(startedAt).Milliseconds(),
			TransportError: sanitizeDiagnosticText(requestErr.Error(), diagnosticTextLimit),
			ErrorChain:     errorFrames(requestErr),
		})
		return requestErr
	}
	if response == nil || (response.StatusCode >= 200 && response.StatusCode < 300) {
		return nil
	}

	statusCode := response.StatusCode
	status := response.Status
	headers := sanitizeDiagnosticHeaders(response.Header)
	var body []byte
	var bodyTruncated bool
	if response.Diagnostic != nil {
		statusCode = response.Diagnostic.StatusCode
		status = response.Diagnostic.Status
		headers = sanitizeDiagnosticHeaders(response.Diagnostic.Header)
		body, bodyTruncated = r.captureBody(response.Diagnostic.Body, response.Diagnostic.BodyTruncated)
	} else {
		var err error
		var replay io.ReadCloser
		body, replay, bodyTruncated, err = readResponseBody(response.Body)
		response.Body = replay
		body, bodyTruncated = r.captureBody(body, bodyTruncated)
		if err != nil {
			r.append(audit.Attempt{
				Source:                audit.AttemptSourceUpstreamHTTP,
				Stage:                 "response_body",
				AccountID:             auditAccountID(credential.ID),
				AccountName:           credential.Name,
				Method:                r.method,
				RequestPath:           r.path,
				UpstreamURL:           sanitizeUpstreamURL(response.UpstreamURL),
				StartedAt:             startedAt.UTC(),
				DurationMS:            time.Since(startedAt).Milliseconds(),
				UpstreamStatusCode:    &statusCode,
				UpstreamStatus:        status,
				ResponseHeaders:       headers,
				ResponseBody:          body,
				ResponseBodyTruncated: bodyTruncated,
				TransportError:        sanitizeDiagnosticText(err.Error(), diagnosticTextLimit),
				ErrorChain:            errorFrames(err),
			})
			return err
		}
	}
	r.append(audit.Attempt{
		Source:                audit.AttemptSourceUpstreamHTTP,
		Stage:                 "upstream_response",
		AccountID:             auditAccountID(credential.ID),
		AccountName:           credential.Name,
		Method:                r.method,
		RequestPath:           r.path,
		UpstreamURL:           sanitizeUpstreamURL(response.UpstreamURL),
		StartedAt:             startedAt.UTC(),
		DurationMS:            time.Since(startedAt).Milliseconds(),
		UpstreamStatusCode:    &statusCode,
		UpstreamStatus:        status,
		ResponseHeaders:       headers,
		ResponseBody:          body,
		ResponseBodyTruncated: bodyTruncated,
	})
	return nil
}

func (r *failureAttemptRecorder) captureStreamFailure(credential accountdomain.Credential, startedAt time.Time, response *provider.Response, diagnostic StreamFailureDiagnostic) {
	r.captureStreamFailureForBranch(0, credential, startedAt, response, diagnostic)
}

func (r *failureAttemptRecorder) captureStreamFailureForBranch(branchID int, credential accountdomain.Credential, startedAt time.Time, response *provider.Response, diagnostic StreamFailureDiagnostic) {
	if response == nil {
		return
	}
	statusCode := response.StatusCode
	body, bodyTruncated := r.captureBody(diagnostic.Body, diagnostic.BodyTruncated)
	r.append(audit.Attempt{
		HedgeBranch:           max(0, branchID),
		Source:                audit.AttemptSourceUpstreamHTTP,
		Stage:                 "response_stream",
		AccountID:             auditAccountID(credential.ID),
		AccountName:           credential.Name,
		Method:                r.method,
		RequestPath:           r.path,
		UpstreamURL:           sanitizeUpstreamURL(response.UpstreamURL),
		StartedAt:             startedAt.UTC(),
		DurationMS:            time.Since(startedAt).Milliseconds(),
		UpstreamStatusCode:    &statusCode,
		UpstreamStatus:        response.Status,
		ResponseHeaders:       sanitizeDiagnosticHeaders(response.Header),
		ResponseBody:          body,
		ResponseBodyTruncated: bodyTruncated,
	})
}

func (r *failureAttemptRecorder) captureRecoveredAttempts(credential accountdomain.Credential, startedAt time.Time, response *provider.Response) {
	if response == nil {
		return
	}
	for _, recovered := range response.RecoveredAttempts {
		diagnostic := recovered.Diagnostic
		body, truncated := r.captureBody(diagnostic.Body, diagnostic.BodyTruncated)
		stage := recovered.Stage
		if stage == "" {
			stage = "recovered_upstream"
		}
		source := audit.AttemptSourceUpstreamHTTP
		var statusCode *int
		if diagnostic.StatusCode != 0 {
			value := diagnostic.StatusCode
			statusCode = &value
		} else {
			source = audit.AttemptSourceTransport
		}
		upstreamURL := recovered.UpstreamURL
		if upstreamURL == "" {
			upstreamURL = response.UpstreamURL
		}
		attemptStartedAt := recovered.StartedAt
		durationMS := recovered.DurationMS
		if attemptStartedAt.IsZero() {
			attemptStartedAt = startedAt
			durationMS = time.Since(startedAt).Milliseconds()
		}
		if durationMS < 0 {
			durationMS = 0
		}
		transportError := recovered.Result
		errorChain := make([]audit.ErrorFrame, 0, 1)
		if recovered.Result != "" {
			errorChain = append(errorChain, audit.ErrorFrame{Type: stage, Message: sanitizeDiagnosticText(recovered.Result, 512)})
		}
		if recovered.Failure != nil {
			failureText := sanitizeDiagnosticText(recovered.Failure.Error(), diagnosticTextLimit)
			if transportError == "" {
				transportError = failureText
			} else {
				transportError = sanitizeDiagnosticText(transportError+": "+failureText, diagnosticTextLimit)
			}
			errorChain = append(errorChain, errorFrames(recovered.Failure)...)
			if len(errorChain) > diagnosticErrorFrameLimit {
				errorChain = errorChain[:diagnosticErrorFrameLimit]
			}
		}
		r.append(audit.Attempt{
			Source:                source,
			Stage:                 stage,
			AccountID:             auditAccountID(credential.ID),
			AccountName:           credential.Name,
			Method:                r.method,
			RequestPath:           r.path,
			UpstreamURL:           sanitizeUpstreamURL(upstreamURL),
			StartedAt:             attemptStartedAt.UTC(),
			DurationMS:            durationMS,
			UpstreamStatusCode:    statusCode,
			UpstreamStatus:        diagnostic.Status,
			ResponseHeaders:       sanitizeDiagnosticHeaders(diagnostic.Header),
			ResponseBody:          body,
			ResponseBodyTruncated: truncated,
			TransportError:        sanitizeDiagnosticText(transportError, diagnosticTextLimit),
			ErrorChain:            errorChain,
		})
	}
}

func (r *failureAttemptRecorder) captureSelectionFailure(accountID uint64, accountName string, err error) {
	if err == nil {
		return
	}
	stage := "account_selection"
	id := accountID
	name := accountName
	var unavailable *SelectionUnavailableError
	if errors.As(err, &unavailable) && unavailable != nil {
		stage = string(unavailable.Reason)
		if unavailable.AccountID != 0 {
			id = unavailable.AccountID
		}
		if unavailable.AccountName != "" {
			name = unavailable.AccountName
		}
	}
	r.append(audit.Attempt{
		Source:         audit.AttemptSourceCredential,
		Stage:          stage,
		AccountID:      auditAccountID(id),
		AccountName:    name,
		Method:         r.method,
		RequestPath:    r.path,
		StartedAt:      time.Now().UTC(),
		TransportError: sanitizeDiagnosticText(err.Error(), diagnosticTextLimit),
		ErrorChain:     errorFrames(err),
	})
}

func (r *failureAttemptRecorder) hasStreamFailureFor(accountID uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasStreamFailureForLocked(accountID)
}

func (r *failureAttemptRecorder) hasStreamFailureForLocked(accountID uint64) bool {
	for _, attempt := range r.attempts {
		if attempt.Stage != "response_stream" || attempt.AccountID == nil || *attempt.AccountID != accountID {
			continue
		}
		return true
	}
	return false
}

// ensureStreamFailureAttempt 补记已完成 2xx 响应头握手、但随后失败的流式尝试。
// 既有 4xx 或传输失败记录不能屏蔽该尝试；同一账号已有 response_stream 时不重复追加。
func (r *failureAttemptRecorder) ensureStreamFailureAttempt(credential accountdomain.Credential, startedAt time.Time, response *provider.Response, errorCode string) {
	r.ensureStreamFailureAttemptForBranch(0, credential, startedAt, response, errorCode)
}

func (r *failureAttemptRecorder) ensureStreamFailureAttemptForBranch(branchID int, credential accountdomain.Credential, startedAt time.Time, response *provider.Response, errorCode string) {
	if response == nil || response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return
	}
	statusCode := response.StatusCode
	attempt := audit.Attempt{
		HedgeBranch:        max(0, branchID),
		Source:             audit.AttemptSourceUpstreamHTTP,
		Stage:              "response_stream",
		AccountID:          auditAccountID(credential.ID),
		AccountName:        credential.Name,
		Method:             r.method,
		RequestPath:        r.path,
		UpstreamURL:        sanitizeUpstreamURL(response.UpstreamURL),
		StartedAt:          startedAt.UTC(),
		DurationMS:         time.Since(startedAt).Milliseconds(),
		UpstreamStatusCode: &statusCode,
		UpstreamStatus:     response.Status,
		ResponseHeaders:    sanitizeDiagnosticHeaders(response.Header),
		TransportError:     errorCode,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hasStreamFailureForLocked(credential.ID) {
		return
	}
	r.appendLocked(attempt)
}

func (r *failureAttemptRecorder) captureQualityDegraded(credential accountdomain.Credential, startedAt time.Time, upstreamURL string, diag QualityPeekDiagnostic) audit.Attempt {
	return r.captureQualityDegradedForBranch(0, credential, startedAt, upstreamURL, diag)
}

func (r *failureAttemptRecorder) captureQualityDegradedForBranch(branchID int, credential accountdomain.Credential, startedAt time.Time, upstreamURL string, diag QualityPeekDiagnostic) audit.Attempt {
	status := http.StatusOK
	durationMS := time.Since(startedAt).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	attempt := audit.Attempt{
		HedgeBranch:        max(0, branchID),
		Source:             audit.AttemptSourceUpstreamHTTP,
		Stage:              attemptStageQualityHold,
		AccountID:          auditAccountID(credential.ID),
		AccountName:        credential.Name,
		Method:             r.method,
		RequestPath:        r.path,
		UpstreamURL:        sanitizeUpstreamURL(upstreamURL),
		StartedAt:          startedAt.UTC(),
		DurationMS:         durationMS,
		UpstreamStatusCode: &status,
		UpstreamStatus:     "200 OK",
		ResponseBody:       marshalQualityDiagnostic(diag),
		TransportError:     qualityDiagnosticTransportError(diag.Reason),
	}
	return r.append(attempt)
}

// captureQualityPeekError 记录 2xx 响应头之后、质量闸门窥探阶段发生的流中断/空流/空闲超时。
func (r *failureAttemptRecorder) captureQualityPeekError(credential accountdomain.Credential, startedAt time.Time, response *provider.Response, diag QualityPeekDiagnostic, peekErr error, branchID int) audit.Attempt {
	if peekErr == nil {
		return audit.Attempt{}
	}
	status := http.StatusOK
	upstreamStatus := "200 OK"
	upstreamURL := sanitizeUpstreamURL(errorUpstreamURL(peekErr))
	var headers map[string][]string
	if response != nil {
		if response.StatusCode >= 100 && response.StatusCode <= 599 {
			status = response.StatusCode
		}
		if response.Status != "" {
			upstreamStatus = response.Status
		}
		if response.UpstreamURL != "" {
			upstreamURL = sanitizeUpstreamURL(response.UpstreamURL)
		}
		headers = sanitizeDiagnosticHeaders(response.Header)
	}
	durationMS := time.Since(startedAt).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	attempt := audit.Attempt{
		HedgeBranch:        max(0, branchID),
		Source:             audit.AttemptSourceUpstreamHTTP,
		Stage:              attemptStageQualityPeekError,
		AccountID:          auditAccountID(credential.ID),
		AccountName:        credential.Name,
		Method:             r.method,
		RequestPath:        r.path,
		UpstreamURL:        upstreamURL,
		StartedAt:          startedAt.UTC(),
		DurationMS:         durationMS,
		UpstreamStatusCode: &status,
		UpstreamStatus:     upstreamStatus,
		ResponseHeaders:    headers,
		ResponseBody:       marshalQualityDiagnostic(diag),
		TransportError:     qualityPeekErrorTransportText(peekErr),
		ErrorChain:         errorFrames(peekErr),
	}
	return r.append(attempt)
}

func qualityPeekErrorTransportText(err error) string {
	if err == nil {
		return attemptStageQualityPeekError
	}
	message := sanitizeDiagnosticText(err.Error(), diagnosticTextLimit)
	if message == "" {
		return attemptStageQualityPeekError
	}
	return sanitizeDiagnosticText(attemptStageQualityPeekError+": "+message, diagnosticTextLimit)
}

func shadowAttemptStage(stage string) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		return attemptStageHedgeShadowFailed
	}
	if strings.HasPrefix(stage, "hedge_shadow") {
		return truncateDiagnosticText(stage, attemptStageMaxLen)
	}
	if stage == attemptStageQualityPeekError {
		return attemptStageHedgeShadowPeekErr
	}
	if stage == attemptStageQualityHold {
		return attemptStageHedgeShadowDegraded
	}
	return truncateDiagnosticText(attemptStageHedgeShadowPrefix+stage, attemptStageMaxLen)
}

func markAttemptsAsHedgeShadow(attempts []audit.Attempt, branchID int) []audit.Attempt {
	if len(attempts) == 0 {
		return nil
	}
	out := make([]audit.Attempt, len(attempts))
	for index, attempt := range attempts {
		attempt.Number = 0
		if attempt.HedgeBranch == 0 && branchID > 0 {
			attempt.HedgeBranch = branchID
		}
		attempt.Stage = shadowAttemptStage(attempt.Stage)
		out[index] = attempt
	}
	return out
}

func filterShadowNonCancelAttempts(attempts []audit.Attempt, branchID int) []audit.Attempt {
	if len(attempts) == 0 {
		return nil
	}
	out := make([]audit.Attempt, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.Stage == "request_canceled" {
			continue
		}
		if attempt.Source == audit.AttemptSourceCredential && strings.Contains(attempt.TransportError, context.Canceled.Error()) {
			continue
		}
		attempt.Number = 0
		if attempt.HedgeBranch == 0 && branchID > 0 {
			attempt.HedgeBranch = branchID
		}
		attempt.Stage = shadowAttemptStage(attempt.Stage)
		out = append(out, attempt)
	}
	return out
}

func buildHedgeShadowQualityAttempt(method, path, stage string, branchID int, credential accountdomain.Credential, startedAt time.Time, response *provider.Response, diag QualityPeekDiagnostic, transportError string) audit.Attempt {
	status := http.StatusOK
	upstreamStatus := "200 OK"
	upstreamURL := ""
	var headers map[string][]string
	if response != nil {
		if response.StatusCode >= 100 && response.StatusCode <= 599 {
			status = response.StatusCode
		}
		if response.Status != "" {
			upstreamStatus = response.Status
		}
		upstreamURL = sanitizeUpstreamURL(response.UpstreamURL)
		headers = sanitizeDiagnosticHeaders(response.Header)
	}
	durationMS := time.Since(startedAt).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	return audit.Attempt{
		HedgeBranch:        max(0, branchID),
		Source:             audit.AttemptSourceUpstreamHTTP,
		Stage:              stage,
		AccountID:          auditAccountID(credential.ID),
		AccountName:        credential.Name,
		Method:             method,
		RequestPath:        sanitizeRequestPath(path),
		UpstreamURL:        upstreamURL,
		StartedAt:          startedAt.UTC(),
		DurationMS:         durationMS,
		UpstreamStatusCode: &status,
		UpstreamStatus:     upstreamStatus,
		ResponseHeaders:    headers,
		ResponseBody:       marshalQualityDiagnostic(diag),
		TransportError:     sanitizeDiagnosticText(transportError, diagnosticTextLimit),
	}
}

func buildHedgeShadowCanceledAttempt(method, path string, branchID int, credential accountdomain.Credential, startedAt time.Time, response *provider.Response, diag QualityPeekDiagnostic, cancelReason string, err error) audit.Attempt {
	if strings.TrimSpace(cancelReason) == "" {
		cancelReason = attemptStageHedgeShadowCanceled
	}
	durationMS := time.Since(startedAt).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	attempt := audit.Attempt{
		HedgeBranch:    max(0, branchID),
		Source:         audit.AttemptSourceTransport,
		Stage:          attemptStageHedgeShadowCanceled,
		AccountID:      auditAccountID(credential.ID),
		AccountName:    credential.Name,
		Method:         method,
		RequestPath:    sanitizeRequestPath(path),
		UpstreamURL:    sanitizeUpstreamURL(errorUpstreamURL(err)),
		StartedAt:      startedAt.UTC(),
		DurationMS:     durationMS,
		TransportError: sanitizeDiagnosticText(cancelReason, diagnosticTextLimit),
		ErrorChain:     errorFrames(err),
	}
	if response != nil && response.StatusCode >= 100 && response.StatusCode <= 599 {
		status := response.StatusCode
		attempt.Source = audit.AttemptSourceUpstreamHTTP
		attempt.UpstreamStatusCode = &status
		attempt.UpstreamStatus = response.Status
		if response.UpstreamURL != "" {
			attempt.UpstreamURL = sanitizeUpstreamURL(response.UpstreamURL)
		}
		attempt.ResponseHeaders = sanitizeDiagnosticHeaders(response.Header)
		attempt.ResponseBody = marshalQualityDiagnostic(diag)
	}
	return attempt
}

func buildHedgeShadowFallbackFailureAttempt(method, path string, branchID int, credential accountdomain.Credential, startedAt time.Time, response *provider.Response, err error) audit.Attempt {
	durationMS := time.Since(startedAt).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	attempt := audit.Attempt{
		HedgeBranch: max(0, branchID),
		Source:      audit.AttemptSourceTransport,
		Stage:       attemptStageHedgeShadowFailed,
		AccountID:   auditAccountID(credential.ID),
		AccountName: credential.Name,
		Method:      method,
		RequestPath: sanitizeRequestPath(path),
		UpstreamURL: sanitizeUpstreamURL(errorUpstreamURL(err)),
		StartedAt:   startedAt.UTC(),
		DurationMS:  durationMS,
	}
	if err != nil {
		attempt.TransportError = sanitizeDiagnosticText(err.Error(), diagnosticTextLimit)
		attempt.ErrorChain = errorFrames(err)
	}
	if response != nil && response.StatusCode >= 100 && response.StatusCode <= 599 {
		status := response.StatusCode
		attempt.Source = audit.AttemptSourceUpstreamHTTP
		attempt.UpstreamStatusCode = &status
		attempt.UpstreamStatus = response.Status
		if response.UpstreamURL != "" {
			attempt.UpstreamURL = sanitizeUpstreamURL(response.UpstreamURL)
		}
		attempt.ResponseHeaders = sanitizeDiagnosticHeaders(response.Header)
	}
	return attempt
}

func (r *failureAttemptRecorder) append(attempt audit.Attempt) audit.Attempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.appendLocked(attempt)
}

func (r *failureAttemptRecorder) appendLocked(attempt audit.Attempt) audit.Attempt {
	if attempt.HedgeBranch == 0 && r.hedgeBranch > 0 {
		attempt.HedgeBranch = r.hedgeBranch
	}
	attempt.Number = len(r.attempts) + 1
	r.attempts = append(r.attempts, attempt)
	return attempt
}

func (r *failureAttemptRecorder) appendAll(attempts []audit.Attempt) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, attempt := range attempts {
		r.appendLocked(attempt)
	}
}

// appendBeforeSeal 尝试在主请求审计尚未封存落库前直接追加到内存记录；
// 若主请求已进入落库流程，则返回 sealed=true 及主审计落库完成信号，交由调用方走数据库追加。
func (r *failureAttemptRecorder) appendBeforeSeal(attempts []audit.Attempt) (bool, <-chan struct{}) {
	if len(attempts) == 0 {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed {
		return true, r.commitDone
	}
	for _, attempt := range attempts {
		r.appendLocked(attempt)
	}
	return false, nil
}

// sealAndSnapshot 封存内存尝试列表并返回快照，供主请求审计写入。
func (r *failureAttemptRecorder) sealAndSnapshot() []audit.Attempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sealed = true
	return append([]audit.Attempt(nil), r.attempts...)
}

// markCommitted 通知等待主审计落库的后台影子质检：主请求审计是否已成功提交。
func (r *failureAttemptRecorder) markCommitted(ok bool) {
	r.mu.Lock()
	r.commitOK = ok
	r.mu.Unlock()
	r.commitDoneOnce.Do(func() {
		if r.commitDone != nil {
			close(r.commitDone)
		}
	})
}

func (r *failureAttemptRecorder) commitSucceeded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.commitOK
}

// captureBody 在单次和单请求预算内保留可读的脱敏正文片段。
func (r *failureAttemptRecorder) captureBody(body []byte, alreadyTruncated bool) ([]byte, bool) {
	if len(body) == 0 {
		return nil, alreadyTruncated
	}
	if !utf8.Valid(body) {
		return nil, true
	}
	body = redactSensitiveDiagnosticJSON(body)
	r.mu.Lock()
	defer r.mu.Unlock()
	limit := min(diagnosticBodyLimit, r.remainingBodyBudget)
	if limit <= 0 {
		return nil, true
	}
	truncated := alreadyTruncated || len(body) > limit
	if len(body) > limit {
		body = body[:limit]
	}
	result := []byte(sanitizeDiagnosticText(string(body), limit))
	r.remainingBodyBudget -= len(result)
	return result, truncated
}

// redactSensitiveDiagnosticJSON 递归替换诊断 JSON 中的密文与 opaque 会话状态。
func redactSensitiveDiagnosticJSON(body []byte) []byte {
	var payload any
	if json.Unmarshal(body, &payload) != nil || !redactSensitiveDiagnosticValue(payload) {
		return body
	}
	redacted, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return redacted
}

// redactSensitiveDiagnosticValue 遍历 JSON 容器，避免嵌套敏感字段绕过顶层脱敏。
func redactSensitiveDiagnosticValue(value any) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if isSensitiveDiagnosticField(key) {
				typed[key] = "[REDACTED]"
				changed = true
				continue
			}
			changed = redactSensitiveDiagnosticValue(nested) || changed
		}
	case []any:
		for _, nested := range typed {
			changed = redactSensitiveDiagnosticValue(nested) || changed
		}
	}
	return changed
}

// isSensitiveDiagnosticField 统一识别上游可能使用的密文与压缩状态字段名。
func isSensitiveDiagnosticField(value string) bool {
	value = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
	value = strings.ReplaceAll(value, "_", "")
	switch value {
	case "encryptedcontent", "compactionblob", "compactionstate", "opaquestate", "opaquedata":
		return true
	default:
		return false
	}
}

func (r *failureAttemptRecorder) snapshot() []audit.Attempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Attempt(nil), r.attempts...)
}

func auditAccountID(id uint64) *uint64 {
	if id == 0 {
		return nil
	}
	return &id
}

type replayReadCloser struct {
	io.Reader
	source io.Closer
}

func (r *replayReadCloser) Close() error { return r.source.Close() }

// readResponseBody 只读取诊断上限，同时把已读取前缀接回原始响应供后续错误处理。
func readResponseBody(body io.ReadCloser) ([]byte, io.ReadCloser, bool, error) {
	if body == nil {
		return nil, io.NopCloser(bytes.NewReader(nil)), false, nil
	}
	data, err := io.ReadAll(io.LimitReader(body, diagnosticBodyLimit+1))
	truncated := len(data) > diagnosticBodyLimit
	if truncated || err != nil {
		captured := data
		if len(captured) > diagnosticBodyLimit {
			captured = captured[:diagnosticBodyLimit]
		}
		replay := &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(data), body), source: body}
		return captured, replay, truncated, err
	}
	closeErr := body.Close()
	return data, io.NopCloser(bytes.NewReader(data)), false, closeErr
}

func errorFrames(err error) []audit.ErrorFrame {
	frames := make([]audit.ErrorFrame, 0, 4)
	appendErrorFrames(&frames, err)
	return frames
}

func appendErrorFrames(frames *[]audit.ErrorFrame, err error) {
	if err == nil || len(*frames) >= diagnosticErrorFrameLimit {
		return
	}
	*frames = append(*frames, audit.ErrorFrame{Type: truncateDiagnosticText(reflect.TypeOf(err).String(), 256), Message: sanitizeDiagnosticText(err.Error(), 512)})
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, nested := range joined.Unwrap() {
			appendErrorFrames(frames, nested)
		}
		return
	}
	appendErrorFrames(frames, errors.Unwrap(err))
}

func sanitizeDiagnosticHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string)
	remaining := diagnosticHeadersLimit
	for name, values := range headers {
		if remaining <= 0 {
			break
		}
		lowerName := strings.ToLower(name)
		if !isAllowedDiagnosticHeader(lowerName) {
			continue
		}
		cleanValues := make([]string, 0, min(len(values), 8))
		for _, value := range values {
			if len(cleanValues) == 8 || remaining <= len(name) {
				break
			}
			cleanValue := sanitizeDiagnosticText(value, min(diagnosticHeaderValueLimit, remaining-len(name)))
			cleanValues = append(cleanValues, cleanValue)
			remaining -= len(name) + len(cleanValue)
		}
		if len(cleanValues) > 0 {
			result[http.CanonicalHeaderKey(name)] = cleanValues
		}
	}
	return result
}

func isAllowedDiagnosticHeader(name string) bool {
	if strings.HasPrefix(name, "x-ratelimit-") || strings.HasPrefix(name, "ratelimit-") {
		return true
	}
	switch name {
	case "content-length", "content-type", "date", "retry-after", "server", "cf-ray", "request-id", "traceparent", "tracestate", "via", "x-correlation-id", "x-request-id", "x-grok2api-compatibility-warnings":
		return true
	default:
		return false
	}
}

func sanitizeDiagnosticText(value string, limit int) string {
	value = diagnosticCookiePattern.ReplaceAllString(value, "$1: [REDACTED]")
	value = diagnosticAuthorizationPattern.ReplaceAllString(value, "$1 [REDACTED]")
	value = diagnosticSecretPattern.ReplaceAllString(value, "$1[REDACTED]")
	value = diagnosticOpaqueFieldPattern.ReplaceAllString(value, "$1[REDACTED]$3")
	value = diagnosticURLPattern.ReplaceAllStringFunc(value, sanitizeUpstreamURL)
	return truncateDiagnosticText(value, limit)
}

func truncateDiagnosticText(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

func sanitizeRequestPath(value string) string {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return truncateDiagnosticText(strings.SplitN(value, "?", 2)[0], 2048)
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return truncateDiagnosticText(parsed.String(), 2048)
}

func sanitizeUpstreamURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return truncateDiagnosticText(parsed.String(), 4096)
}

func errorUpstreamURL(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.URL
	}
	return ""
}

func transportStage(err error) string {
	switch {
	case neterrorpkg.IsResponseHeaderTimeout(err):
		return "response_header_timeout"
	case errors.Is(err, context.Canceled):
		return "request_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "request_timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_lookup"
	}
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return "tls_verification"
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "tls_verification"
	}
	var recordHeaderError tls.RecordHeaderError
	if errors.As(err, &recordHeaderError) {
		return "tls_handshake"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "network_timeout"
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) && operationError.Op != "" {
		return operationError.Op
	}
	return "transport"
}
