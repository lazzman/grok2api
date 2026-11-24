package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	clientkeyapp "github.com/chenyme/grok2api/backend/internal/application/clientkey"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/clientkey"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	inferencedomain "github.com/chenyme/grok2api/backend/internal/domain/inference"
	"github.com/chenyme/grok2api/backend/internal/infra/runtime/memory"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

type hedgeScriptedAdapter struct {
	mu       sync.Mutex
	launched []uint64
	handlers map[uint64]func(ctx context.Context, req provider.ResponseResourceRequest) (*provider.Response, error)
}

func (a *hedgeScriptedAdapter) Provider() accountdomain.Provider { return accountdomain.ProviderBuild }

func (a *hedgeScriptedAdapter) Definition() provider.Definition {
	definition := testConversationDefinition(accountdomain.ProviderBuild)
	definition.Conversation.StoredResponses = true
	definition.Conversation.Compact = true
	return definition
}

func (a *hedgeScriptedAdapter) ForwardResponse(ctx context.Context, req provider.ResponseResourceRequest) (*provider.Response, error) {
	a.mu.Lock()
	a.launched = append(a.launched, req.Credential.ID)
	handler := a.handlers[req.Credential.ID]
	a.mu.Unlock()
	if handler == nil {
		return &provider.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}
	return handler(ctx, req)
}

func (a *hedgeScriptedAdapter) RefreshCredential(context.Context, accountdomain.Credential) (provider.RefreshedCredential, error) {
	return provider.RefreshedCredential{}, nil
}

func (a *hedgeScriptedAdapter) DiscoverModels(context.Context, accountdomain.Credential) ([]string, error) {
	return nil, nil
}

func (a *hedgeScriptedAdapter) Launched() []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]uint64(nil), a.launched...)
}

type hedgeTestAccountSpec struct {
	name       string
	priority   int
	teamID     string
	egressName string
}

func setupHedgeGatewayTest(
	t *testing.T,
	specs []hedgeTestAccountSpec,
	cfg QualityRetryRuntime,
	handlers map[int]func(ctx context.Context, req provider.ResponseResourceRequest) (*provider.Response, error),
) (*Service, *relational.AccountRepository, *relational.AuditRepository, []accountdomain.Credential, clientkey.Key, *hedgeScriptedAdapter) {
	t.Helper()
	ctx := context.Background()
	db, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "quality-hedge.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeSchema(ctx); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	accountRepo := relational.NewAccountRepository(db)
	modelRepo := relational.NewModelRepository(db)
	auditRepo := relational.NewAuditRepository(db)
	responseRepo := relational.NewResponseRepository(db)
	keyRepo := relational.NewClientKeyRepository(db)

	egressRepo := relational.NewEgressRepository(db)
	egressIDs := make(map[string]uint64)
	creds := make([]accountdomain.Credential, 0, len(specs))
	byID := make(map[uint64]func(ctx context.Context, req provider.ResponseResourceRequest) (*provider.Response, error), len(specs))
	for index, spec := range specs {
		var egressNodeID uint64
		if spec.egressName != "" {
			if id, exists := egressIDs[spec.egressName]; exists {
				egressNodeID = id
			} else {
				node, nodeErr := egressRepo.CreateEgressNode(ctx, egressdomain.Node{
					Name: spec.egressName, Scope: egressdomain.ScopeBuild, Enabled: true, EncryptedProxyURL: "encrypted-" + spec.egressName,
				})
				if nodeErr != nil {
					_ = db.Close()
					t.Fatal(nodeErr)
				}
				egressIDs[spec.egressName] = node.ID
				egressNodeID = node.ID
			}
		}
		prio := spec.priority
		if prio == 0 {
			prio = 300 - index*10
		}
		cred, _, createErr := accountRepo.UpsertByIdentity(ctx, accountdomain.Credential{
			Provider:              accountdomain.ProviderBuild,
			Name:                  spec.name,
			SourceKey:             spec.name,
			EncryptedAccessToken:  spec.name,
			EncryptedRefreshToken: "refresh-" + spec.name,
			ExpiresAt:             time.Now().Add(time.Hour),
			Enabled:               true,
			AuthStatus:            accountdomain.AuthStatusActive,
			Priority:              prio,
			MaxConcurrent:         1,
			TeamID:                spec.teamID,
			EgressNodeID:          egressNodeID,
		})
		if createErr != nil {
			_ = db.Close()
			t.Fatal(createErr)
		}
		creds = append(creds, cred)
		if h, ok := handlers[index]; ok {
			byID[cred.ID] = h
		}
	}
	if err := modelRepo.UpsertDiscovered(ctx, accountdomain.ProviderBuild, []string{"grok-4.7"}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	for _, cred := range creds {
		if err := modelRepo.ReplaceAccountCapabilities(ctx, cred.ID, []string{"grok-4.7"}, time.Now().UTC()); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	key, err := keyRepo.Create(ctx, clientkey.Key{
		Name:            "hedge-key",
		Prefix:          "hdg",
		SecretHash:      strings.Repeat("f", 64),
		EncryptedSecret: "encrypted",
		Enabled:         true,
		RPMLimit:        120,
		MaxConcurrent:   8,
	})
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	adapter := &hedgeScriptedAdapter{handlers: byID}
	registry := provider.NewRegistry(adapter)
	sticky := memory.NewStickyStore()
	accountService := accountapp.NewService(accountRepo, auditRepo, memory.NewDeviceSessionStore(), sticky, registry, testCipher(t), nil)
	selector := NewSelector(accountRepo, memory.NewConcurrencyLimiter(), sticky, registry, time.Hour, time.Second, time.Minute)
	service := NewService(modelRepo, auditRepo, accountService, clientkeyapp.NewService(nil, nil, nil, 60, 4, nil), registry, selector, responseRepo, 6)
	service.UpdateQualityRetry(cfg)
	t.Cleanup(func() {
		service.WaitShadowQualityProbes()
		_ = db.Close()
	})
	return service, accountRepo, auditRepo, creds, key, adapter
}

func goodPlaintextSSE(id, text string) string {
	return sse(
		`data: {"type":"response.created","response":{"id":"`+id+`","model":"grok-4.7"}}`,
		`data: {"type":"response.reasoning_summary_text.delta","delta":"thinking cleanly"}`,
		`data: {"type":"response.output_text.delta","delta":"`+text+`"}`,
		`data: {"type":"response.completed","response":{"id":"`+id+`","model":"grok-4.7","usage":{"input_tokens":100,"output_tokens":40,"output_tokens_details":{"reasoning_tokens":20}}}}`,
	)
}

func TestHedgeFastPrimaryDoesNotLaunchSecondAccount(t *testing.T) {
	ctx := context.Background()
	service, _, _, creds, key, adapter := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{{name: "fast-1"}, {name: "backup-2"}},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 3, MinOutputTokens: 8,
			HoldTimeout: 300 * time.Millisecond, OnExhausted: qualityRetryFailClosed,
			HedgeEnabled: true, HedgeDelay: 120 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(goodPlaintextSSE("resp-fast", "answer-1"))),
				}, nil
			},
			1: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				t.Error("fast primary delivered before hedgeDelay; 2nd account must not be launched")
				return nil, context.Canceled
			},
		},
	)
	res, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-fast", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Finalize(Usage{Reported: true, OutputTokens: 40, ReasoningTokens: 20}, "resp-fast", "")
	_ = res.Body.Close()
	if !strings.Contains(string(body), "answer-1") {
		t.Fatalf("unexpected body: %s", body)
	}
	launched := adapter.Launched()
	if len(launched) != 1 || launched[0] != creds[0].ID {
		t.Fatalf("launched = %v, want only primary %d", launched, creds[0].ID)
	}
}

func TestHedgeStaggeredWinnerDeliversAndShadowCatchesDegradedPrimary(t *testing.T) {
	ctx := context.Background()
	service, accounts, audits, creds, key, adapter := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{{name: "silent-degraded-1"}, {name: "healthy-2"}},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 3, MinOutputTokens: 8,
			HoldTimeout: 160 * time.Millisecond, OnExhausted: qualityRetryFailClosed,
			AutoDisable: true, HedgeEnabled: true, HedgeDelay: 40 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(bctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				// 静默不吐思考明文，模拟截图中的降智长静默流。
				reader, writer := io.Pipe()
				go func() {
					_, _ = io.WriteString(writer, sse(`data: {"type":"response.created","response":{"id":"resp-silent","model":"grok-4.7"}}`))
					<-bctx.Done()
					_ = writer.Close()
				}()
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					UpstreamURL: "https://build.example/v1/responses", Body: reader,
				}, nil
			},
			1: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(goodPlaintextSSE("resp-win-2", "answer-from-2"))),
				}, nil
			},
		},
	)
	var logBuf bytes.Buffer
	service.logger = slog.New(slog.NewJSONHandler(&logBuf, nil))

	started := time.Now()
	res, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-shadow-degraded", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed >= 140*time.Millisecond {
		t.Fatalf("winner should deliver right after hedgeDelay (~40ms) without waiting holdTimeout (160ms), got %s", elapsed)
	}
	body, _ := io.ReadAll(res.Body)
	res.Finalize(Usage{Reported: true, InputTokens: 100, OutputTokens: 40, ReasoningTokens: 20}, "resp-win-2", "")
	_ = res.Body.Close()
	if !strings.Contains(string(body), "answer-from-2") {
		t.Fatalf("expected winner body from account 2, got: %s", body)
	}

	// 等待后台影子质检跑完 holdTimeout 并自动停用降智的账号 1。
	service.WaitShadowQualityProbes()

	launched := adapter.Launched()
	if len(launched) != 2 || launched[0] != creds[0].ID || launched[1] != creds[1].ID {
		t.Fatalf("launched = %v, want [%d %d]", launched, creds[0].ID, creds[1].ID)
	}
	badAcc, err := accounts.Get(ctx, creds[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if badAcc.Enabled || badAcc.LastError != lastErrorMissingThinkingDisabled {
		t.Fatalf("shadow quality probe must auto-disable degraded account 1, got %#v", badAcc)
	}
	goodAcc, err := accounts.Get(ctx, creds[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !goodAcc.Enabled {
		t.Fatalf("winner account 2 must stay enabled, got %#v", goodAcc)
	}

	logs, _, err := audits.List(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var degradedID uint64
	normalCount := 0
	for _, row := range logs {
		if row.ErrorCode == ErrorQualityDegraded && row.AccountID != nil && *row.AccountID == creds[0].ID {
			degradedID = row.ID
		}
		if row.ErrorCode == "" {
			normalCount++
		}
	}
	if normalCount != 1 || degradedID == 0 {
		t.Fatalf("expected 1 normal audit (winner) and 1 shadow degraded audit, logs=%#v", logs)
	}
	detail, err := audits.Get(ctx, degradedID)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Attempts) != 1 || detail.Attempts[0].TransportError != "quality_degraded: missing_thinking_hold_expired" {
		t.Fatalf("shadow degraded attempt mismatch: %#v", detail.Attempts)
	}
	var parsed QualityPeekDiagnostic
	if err := json.Unmarshal(detail.Attempts[0].ResponseBody, &parsed); err != nil || parsed.Reason != QualityWithholdMissingThinkingExpire {
		t.Fatalf("shadow diagnostic mismatch: err=%v parsed=%#v", err, parsed)
	}
	logText := logBuf.String()
	if !strings.Contains(logText, `"msg":"quality_hedge_shadow_degraded"`) || !strings.Contains(logText, `"hedge_shadow":true`) {
		t.Fatalf("expected shadow degraded log, got:\n%s", logText)
	}
}

func TestHedgeShadowHealthySlowPrimaryIsClosedWithoutPenalty(t *testing.T) {
	ctx := context.Background()
	var primaryClosed atomic.Bool
	service, accounts, audits, creds, key, _ := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{{name: "slow-healthy-1"}, {name: "fast-2"}},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 3, MinOutputTokens: 8,
			HoldTimeout: 400 * time.Millisecond, OnExhausted: qualityRetryFailClosed,
			AutoDisable: true, HedgeEnabled: true, HedgeDelay: 30 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(bctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				reader, writer := io.Pipe()
				go func() {
					defer func() {
						primaryClosed.Store(true)
						_ = writer.Close()
					}()
					_, _ = io.WriteString(writer, sse(`data: {"type":"response.created","response":{"id":"resp-slow-ok","model":"grok-4.7"}}`))
					select {
					case <-time.After(80 * time.Millisecond):
						_, _ = io.WriteString(writer, sse(`data: {"type":"response.reasoning_summary_text.delta","delta":"slow but real reasoning"}`))
					case <-bctx.Done():
					}
					<-bctx.Done()
				}()
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: reader,
				}, nil
			},
			1: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(goodPlaintextSSE("resp-fast-2", "fast-winner"))),
				}, nil
			},
		},
	)
	var logBuf bytes.Buffer
	service.logger = slog.New(slog.NewJSONHandler(&logBuf, nil))

	res, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-shadow-healthy", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	res.Finalize(Usage{Reported: true, OutputTokens: 40, ReasoningTokens: 20}, "resp-fast-2", "")
	_ = res.Body.Close()

	service.WaitShadowQualityProbes()

	if !primaryClosed.Load() {
		t.Fatal("shadow healthy branch stream must be closed immediately once thinking plaintext arrives")
	}
	acc1, err := accounts.Get(ctx, creds[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !acc1.Enabled || acc1.LastError != "" || acc1.CooldownUntil != nil {
		t.Fatalf("healthy slow shadow account must not be penalized: %#v", acc1)
	}
	logs, _, err := audits.List(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].ErrorCode != "" || logs[0].AccountID == nil || *logs[0].AccountID != creds[1].ID {
		t.Fatalf("healthy shadow branch must not write degraded or duplicate audit, logs=%#v", logs)
	}
	if !strings.Contains(logBuf.String(), `"msg":"quality_hedge_shadow_healthy"`) {
		t.Fatalf("expected shadow healthy log, got:\n%s", logBuf.String())
	}
}

func TestHedgeEarlyFailureLaunchesNextImmediatelyWithoutWaitingHedgeDelay(t *testing.T) {
	ctx := context.Background()
	service, _, _, creds, key, adapter := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{{name: "rate-limited-1"}, {name: "ok-2"}},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 3, MinOutputTokens: 8,
			HoldTimeout: 500 * time.Millisecond, OnExhausted: qualityRetryFailClosed,
			HedgeEnabled: true, HedgeDelay: 400 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				return &provider.Response{
					StatusCode: http.StatusTooManyRequests, Status: "429 Too Many Requests", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"error":{"message":"rate limited"}}`)),
				}, nil
			},
			1: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(goodPlaintextSSE("resp-ok-2", "fast-recover"))),
				}, nil
			},
		},
	)
	started := time.Now()
	res, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-early-fail", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	_, _ = io.ReadAll(res.Body)
	res.Finalize(Usage{Reported: true, OutputTokens: 40, ReasoningTokens: 20}, "resp-ok-2", "")
	_ = res.Body.Close()
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("early 429 must immediately launch account 2 without waiting 400ms hedgeDelay, got %s", elapsed)
	}
	if launched := adapter.Launched(); len(launched) != 2 || launched[0] != creds[0].ID || launched[1] != creds[1].ID {
		t.Fatalf("launched = %v, want [%d %d]", launched, creds[0].ID, creds[1].ID)
	}
}

func TestHedgePrefersDifferentTeamAndEgressNode(t *testing.T) {
	ctx := context.Background()
	service, _, _, creds, key, adapter := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{
			{name: "teamA-egress10-first", priority: 300, teamID: "team-a", egressName: "egress-10"},
			{name: "teamA-egress10-second", priority: 250, teamID: "team-a", egressName: "egress-10"},
			{name: "teamB-egress20-diverse", priority: 200, teamID: "team-b", egressName: "egress-20"},
		},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 3, MinOutputTokens: 8,
			HoldTimeout: 250 * time.Millisecond, OnExhausted: qualityRetryFailClosed,
			HedgeEnabled: true, HedgeDelay: 30 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(bctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				reader, writer := io.Pipe()
				go func() {
					<-bctx.Done()
					_ = writer.Close()
				}()
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: reader,
				}, nil
			},
			2: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(goodPlaintextSSE("resp-diverse", "diverse-win"))),
				}, nil
			},
		},
	)
	res, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-diverse", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	res.Finalize(Usage{Reported: true, OutputTokens: 40, ReasoningTokens: 20}, "resp-diverse", "")
	_ = res.Body.Close()

	launched := adapter.Launched()
	if len(launched) != 2 || launched[0] != creds[0].ID || launched[1] != creds[2].ID {
		t.Fatalf("2nd hedge branch should prefer diverse team/egress account %d over same-team account %d, got %v", creds[2].ID, creds[1].ID, launched)
	}
}

func TestHedgeShadowSlotSaturationCancelsLoserWithoutPenalty(t *testing.T) {
	ctx := context.Background()
	var primaryCanceled atomic.Bool
	service, accounts, _, creds, key, _ := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{{name: "slow-1"}, {name: "fast-2"}},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 2, MinOutputTokens: 8,
			HoldTimeout: 500 * time.Millisecond, OnExhausted: qualityRetryFailClosed,
			AutoDisable: true, HedgeEnabled: true, HedgeDelay: 30 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(bctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				<-bctx.Done()
				primaryCanceled.Store(true)
				return nil, bctx.Err()
			},
			1: func(_ context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(goodPlaintextSSE("resp-2", "ok"))),
				}, nil
			},
		},
	)
	// 占满全局影子质检槽位，验证降级为胜出立刻取消且不误伤惩罚。
	for i := 0; i < cap(service.shadowQualitySlots); i++ {
		service.shadowQualitySlots <- struct{}{}
	}
	defer func() {
		for len(service.shadowQualitySlots) > 0 {
			<-service.shadowQualitySlots
		}
	}()

	res, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-shadow-full", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	res.Finalize(Usage{Reported: true, OutputTokens: 40, ReasoningTokens: 20}, "resp-2", "")
	_ = res.Body.Close()
	service.WaitShadowQualityProbes()

	if !primaryCanceled.Load() {
		t.Fatal("saturated shadow slots must cancel losing branch immediately")
	}
	acc1, err := accounts.Get(ctx, creds[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !acc1.Enabled || acc1.LastError != "" || acc1.CooldownUntil != nil {
		t.Fatalf("canceled branch must not be penalized when shadow slots are full: %#v", acc1)
	}
}

func TestHedgeClientCancelAbortsAllInFlightWithoutPenalty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var startedCount atomic.Int32
	var canceledCount atomic.Int32
	twoLaunched := make(chan struct{})
	service, accounts, _, creds, key, _ := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{{name: "hang-1"}, {name: "hang-2"}},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 2, MinOutputTokens: 8,
			HoldTimeout: 2 * time.Second, OnExhausted: qualityRetryFailClosed,
			AutoDisable: true, HedgeEnabled: true, HedgeDelay: 25 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(bctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				if startedCount.Add(1) == 2 {
					close(twoLaunched)
				}
				<-bctx.Done()
				canceledCount.Add(1)
				return nil, bctx.Err()
			},
			1: func(bctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				if startedCount.Add(1) == 2 {
					close(twoLaunched)
				}
				<-bctx.Done()
				canceledCount.Add(1)
				return nil, bctx.Err()
			},
		},
	)
	go func() {
		<-twoLaunched
		cancel()
	}()
	_, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-cancel", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err == nil {
		t.Fatal("expected request_canceled error")
	}
	if canceledCount.Load() != 2 {
		t.Fatalf("canceledCount = %d, want 2", canceledCount.Load())
	}
	for _, cred := range creds {
		acc, getErr := accounts.Get(context.Background(), cred.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if !acc.Enabled || acc.LastError != "" || acc.CooldownUntil != nil {
			t.Fatalf("client-canceled account must not be penalized: %#v", acc)
		}
	}
}

func TestShouldHedgeQualityStreamGuards(t *testing.T) {
	t.Parallel()
	cfg := normalizeQualityRetry(QualityRetryRuntime{Enabled: true, HedgeEnabled: true, HedgeDelay: 8 * time.Second, HedgeMaxConcurrent: 2})
	policy := newRequestRoutingAttemptPolicy(6, false)
	baseInput := Input{Streaming: true, Body: []byte(`{"model":"grok-4.7","input":"hi","stream":true}`)}

	if !shouldHedgeQualityStream(baseInput, nil, true, true, policy, cfg) {
		t.Fatal("eligible streaming request must allow hedging")
	}
	if shouldHedgeQualityStream(baseInput, &inferencedomain.ResponseOwnership{AccountID: 1}, true, true, policy, cfg) {
		t.Fatal("stored response ownership must disable hedging")
	}
	if shouldHedgeQualityStream(Input{Streaming: true, ForcedAccountID: 1, Body: baseInput.Body}, nil, true, true, policy, cfg) {
		t.Fatal("forced account must disable hedging")
	}
	if shouldHedgeQualityStream(baseInput, nil, true, false, policy, cfg) {
		t.Fatal("replay-unsafe request must disable hedging")
	}
	if shouldHedgeQualityStream(baseInput, nil, true, true, newRequestRoutingAttemptPolicy(1, false), cfg) {
		t.Fatal("maxAttempts=1 must disable hedging")
	}
}

func TestHedgeSingleAccountPoolWaitsAndDeliversNormally(t *testing.T) {
	ctx := context.Background()
	service, _, _, creds, key, adapter := setupHedgeGatewayTest(
		t,
		[]hedgeTestAccountSpec{{name: "only-account"}},
		QualityRetryRuntime{
			Enabled: true, MaxAttempts: 3, MinOutputTokens: 8,
			HoldTimeout: 300 * time.Millisecond, OnExhausted: qualityRetryFailClosed,
			HedgeEnabled: true, HedgeDelay: 25 * time.Millisecond, HedgeMaxConcurrent: 2,
		},
		map[int]func(context.Context, provider.ResponseResourceRequest) (*provider.Response, error){
			0: func(bctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
				reader, writer := io.Pipe()
				go func() {
					defer writer.Close()
					select {
					case <-time.After(60 * time.Millisecond):
						_, _ = io.WriteString(writer, goodPlaintextSSE("resp-only", "single-account-ok"))
					case <-bctx.Done():
					}
				}()
				return &provider.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: reader,
				}, nil
			},
		},
	)
	res, err := service.CreateResponse(ctx, Input{
		RequestID: "req-hedge-single", ClientKey: key, PublicModel: "grok-4.7", Streaming: true,
		Body: []byte(`{"model":"grok-4.7","input":"hello","stream":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Finalize(Usage{Reported: true, OutputTokens: 40, ReasoningTokens: 20}, "resp-only", "")
	_ = res.Body.Close()
	if !strings.Contains(string(body), "single-account-ok") {
		t.Fatalf("unexpected body: %s", body)
	}
	if launched := adapter.Launched(); len(launched) != 1 || launched[0] != creds[0].ID {
		t.Fatalf("launched = %v, want [%d]", launched, creds[0].ID)
	}
}
