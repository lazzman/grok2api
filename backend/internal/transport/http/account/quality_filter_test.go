package account

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
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
