package account

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	auditdomain "github.com/chenyme/grok2api/backend/internal/domain/audit"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"github.com/gin-gonic/gin"
)

func TestListAccountQualityFilter(test *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(test.TempDir(), "quality-filter-http.db"))
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		test.Fatal(err)
	}
	accounts := relational.NewAccountRepository(database)
	for _, seed := range []struct {
		name    string
		marker  string
		enabled bool
	}{
		{"clean", "", true},
		{"history", accountdomain.LastErrorMissingThinking, true},
		{"reenabled", accountdomain.LastErrorMissingThinkingDisabled, true},
		{"disabled", accountdomain.LastErrorMissingThinkingDisabled, false},
	} {
		value, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
			Provider: accountdomain.ProviderBuild, Name: seed.name, SourceKey: seed.name, EncryptedAccessToken: "token",
			Enabled: seed.enabled, AuthStatus: accountdomain.AuthStatusActive, Priority: 1, MaxConcurrent: 1,
		})
		if err != nil {
			test.Fatal(err)
		}
		if err := accounts.UpdateHealth(ctx, value.ID, value.Provider, 0, nil, seed.marker, false); err != nil {
			test.Fatal(err)
		}
		if _, err := accounts.UpdateMany(ctx, value.Provider, []uint64{value.ID}, repository.AccountUpdates{Enabled: &seed.enabled}); err != nil {
			test.Fatal(err)
		}
	}
	handler := NewHandler(accountapp.NewService(accounts, relational.NewAuditRepository(database), nil, nil, nil, nil, nil), nil)
	for _, scenario := range []struct {
		query string
		name  string
		total int
	}{
		{"quality=none", "clean", 1},
		{"quality=history", "history", 2},
		{"quality=history&page=2&status=active", "reenabled", 2},
		{"quality=disabled&status=disabled", "disabled", 1},
		{"quality=history&search=reenabled", "reenabled", 1},
		{"quality=history&status=disabled", "", 0},
		{"quality=", "clean", 4},
		{"", "clean", 4},
		{"quality=invalid", "", -1},
		{"qualityWindow=invalid", "", -1},
	} {
		test.Run(scenario.query, func(test *testing.T) {
			recorder := httptest.NewRecorder()
			ginContext, _ := gin.CreateTestContext(recorder)
			ginContext.Request = httptest.NewRequest(http.MethodGet, "/api/admin/v1/accounts?provider=grok_build&pageSize=1&sortBy=name&sortOrder=asc&"+scenario.query, nil)
			handler.list(ginContext)
			var payload struct {
				Data struct {
					Items []struct {
						Name string `json:"name"`
					} `json:"items"`
					Total int `json:"total"`
				} `json:"data"`
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				test.Fatal(err)
			}
			if scenario.total < 0 {
				if recorder.Code != http.StatusBadRequest || payload.Error.Code != "invalidFilter" {
					test.Fatalf("非法筛选未被拒绝：状态 %d，响应 %s", recorder.Code, recorder.Body.String())
				}
				return
			}
			if recorder.Code != http.StatusOK || payload.Data.Total != scenario.total || len(payload.Data.Items) != min(scenario.total, 1) {
				test.Fatalf("筛选响应不符：状态 %d，响应 %s", recorder.Code, recorder.Body.String())
			}
			if scenario.total > 0 && payload.Data.Items[0].Name != scenario.name {
				test.Fatalf("账号 = %s，期望 %s", payload.Data.Items[0].Name, scenario.name)
			}
		})
	}
}

func TestQualityGuardLeaseVisibleInAccountList(test *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(test.TempDir(), "quality-guard-accounts.db"))
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		test.Fatal(err)
	}
	accounts := relational.NewAccountRepository(database)
	audits := relational.NewAuditRepository(database)
	node, err := relational.NewEgressRepository(database).CreateEgressNode(ctx, egressdomain.Node{Name: "共享出口", Scope: egressdomain.ScopeBuild, Enabled: true, EncryptedProxyURL: "encrypted"})
	if err != nil {
		test.Fatal(err)
	}
	now := time.Now().UTC()
	until := now.Add(12 * time.Hour)
	var accountIDs []uint64
	for _, reason := range []string{"hard_tps", "soft_tps"} {
		value, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
			Provider: accountdomain.ProviderBuild, Name: reason, SourceKey: reason, Enabled: true, AuthStatus: accountdomain.AuthStatusActive, EncryptedAccessToken: "token",
		})
		if err != nil {
			test.Fatal(err)
		}
		accountIDs = append(accountIDs, value.ID)
		if _, err := accounts.UpsertEgressLeaseBlock(ctx, accountdomain.EgressLeaseBlock{AccountID: value.ID, NodeID: node.ID, Reason: reason, Version: "lease-private-version", CooldownUntil: until}); err != nil {
			test.Fatal(err)
		}
		firstToken := int64(100)
		output := int64(750)
		if reason == "hard_tps" {
			output = 3500
		}
		if err := audits.Create(ctx, auditdomain.Record{
			RequestID: "user-" + reason, ClientKeyID: 1, ModelRouteID: 1, Provider: "grok_build", AccountID: &value.ID, EgressNodeID: &node.ID, StatusCode: 200, Streaming: true,
			OutputTokens: output, FirstTokenMS: &firstToken, DurationMS: 1100, CreatedAt: now.Add(-time.Minute),
		}); err != nil {
			test.Fatal(err)
		}
	}
	guard, err := audits.SummarizeDegrade(ctx, repository.DegradeSummaryQuery{Start: now.Add(-24 * time.Hour), End: now, SoftTPS: 500, HardTPS: 1000, MinGenerationMS: 1000, MinOutputTokens: 32})
	if err != nil || len(guard.Accounts) != 2 || guard.Totals.Soft != 1 || guard.Totals.Hard != 1 {
		test.Fatalf("未复现质量守护速率异常：%#v，%v", guard, err)
	}
	service := accountapp.NewService(accounts, audits, nil, nil, nil, nil, nil)
	handler := NewHandler(service, nil)
	for _, scenario := range []struct {
		query string
		total int
		name  string
	}{
		{"quality=quarantined", 2, "hard_tps"},
		{"quality=history", 2, "hard_tps"},
		{"quality=history&softTPS=1000&hardTPS=4000", 1, "hard_tps"},
		{"quality=history&softTPS=4000&hardTPS=5000", 0, ""},
		{"quality=marked&page=2", 2, "soft_tps"},
		{"quality=quarantined&status=cooldown", 2, "hard_tps"},
		{"quality=quarantined&search=soft_tps", 1, "soft_tps"},
		{"quality=quarantined&status=active", 0, ""},
		{"quality=disabled", 0, ""},
		{"quality=none", 0, ""},
	} {
		test.Run(scenario.query, func(test *testing.T) {
			recorder := httptest.NewRecorder()
			ginContext, _ := gin.CreateTestContext(recorder)
			ginContext.Request = httptest.NewRequest(http.MethodGet, "/api/admin/v1/accounts?provider=grok_build&pageSize=1&sortBy=name&sortOrder=asc&"+scenario.query, nil)
			handler.list(ginContext)
			var payload struct {
				Data struct {
					Items []accountResponse `json:"items"`
					Total int               `json:"total"`
				} `json:"data"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				test.Fatal(err)
			}
			if recorder.Code != http.StatusOK || payload.Data.Total != scenario.total || len(payload.Data.Items) != min(1, scenario.total) {
				test.Fatalf("筛选响应不符：%d，%s", recorder.Code, recorder.Body.String())
			}
			if scenario.total == 0 {
				return
			}
			item := payload.Data.Items[0]
			if item.Name != scenario.name || !item.Enabled || item.LastError != "" || item.LeaseQuarantinedUntil == nil || !item.LeaseQuarantinedUntil.Equal(until) || item.LeaseQuarantineNodeID != node.ID || item.LeaseQuarantineReason != scenario.name {
				test.Fatalf("隔离详情缺失或错误地改写了账号健康状态：%#v", item)
			}
			if item.QualityHistory == nil || item.QualityHistory.Hits != 1 || !item.QualityHistory.Last.Equal(now.Add(-time.Minute)) {
				test.Fatalf("历史降智信息未序列化：%#v", item)
			}
			if strings.Contains(recorder.Body.String(), "lease-private-version") {
				test.Fatal("隔离版本令牌不应暴露给前端")
			}
		})
	}
	view, err := service.Get(ctx, accountIDs[0])
	if err != nil || view.QualityLease == nil {
		test.Fatalf("账号详情遗漏隔离：%#v，%v", view, err)
	}
	view, err = service.ClearCooldown(ctx, accountIDs[0])
	if err != nil || view.QualityLease == nil || !view.Credential.Enabled || view.Credential.LastError != "" {
		test.Fatalf("解除冷却不应改动出口隔离：%#v，%v", view, err)
	}
	for _, accountID := range accountIDs {
		if deleted, err := accounts.DeleteEgressLeaseBlock(ctx, accountID, node.ID, "lease-private-version"); err != nil || !deleted {
			test.Fatalf("解除隔离失败：%v", err)
		}
		view, err := service.Get(ctx, accountID)
		if err != nil || view.QualityLease != nil {
			test.Fatalf("解除隔离后标签仍残留：%#v，%v", view, err)
		}
	}
	values, total, err := service.List(ctx, 1, 20, "#"+strconv.FormatUint(accountIDs[0], 10), accountapp.ListFilter{Quality: "marked"})
	if err != nil || total != 1 || len(values) != 1 || values[0].QualityHistory == nil || values[0].QualityHistory.Hard != 1 || values[0].QualityLease != nil {
		test.Fatalf("解除隔离后仍应能查到历史降智，且不再显示隔离：%#v，%d，%v", values, total, err)
	}
	older, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{Provider: accountdomain.ProviderBuild, Name: "older-soft", SourceKey: "older-soft", EncryptedAccessToken: "token", Enabled: true, AuthStatus: accountdomain.AuthStatusActive})
	if err != nil {
		test.Fatal(err)
	}
	first := int64(100)
	if err := audits.Create(ctx, auditdomain.Record{RequestID: "user-older-soft", ClientKeyID: 1, ModelRouteID: 1, Provider: "grok_build", AccountID: &older.ID, StatusCode: 200, Streaming: true, OutputTokens: 750, FirstTokenMS: &first, DurationMS: 1100, CreatedAt: now.Add(-2 * time.Hour)}); err != nil {
		test.Fatal(err)
	}
	for _, window := range []string{"1h", "6h", "24h", "7d"} {
		recorder := httptest.NewRecorder()
		ginContext, _ := gin.CreateTestContext(recorder)
		ginContext.Request = httptest.NewRequest(http.MethodGet, "/api/admin/v1/accounts?provider=grok_build&quality=history&search=older-soft&qualityWindow="+window, nil)
		handler.list(ginContext)
		var payload struct {
			Data struct {
				Total int               `json:"total"`
				Items []accountResponse `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			test.Fatal(err)
		}
		want := 1
		if window == "1h" {
			want = 0
		}
		if recorder.Code != http.StatusOK || payload.Data.Total != want || len(payload.Data.Items) != want {
			test.Fatalf("%s 的历史范围未生效：%s", window, recorder.Body.String())
		}
		if want > 0 && (payload.Data.Items[0].QualityHistory == nil || payload.Data.Items[0].QualityHistory.Soft != 1 || payload.Data.Items[0].LeaseQuarantinedUntil != nil) {
			test.Fatalf("无隔离的历史soft应可见：%#v", payload)
		}
	}
}
