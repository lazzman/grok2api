package relational

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestAccountDegradeHistoryMatchesQualityGuard(test *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(test.TempDir(), "account-degrade-history.db"))
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		test.Fatal(err)
	}
	accounts := NewAccountRepository(database)
	audits := NewAuditRepository(database)
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	firstToken := int64(100)
	ids := map[string]uint64{}
	for _, seed := range []struct {
		name     string
		output   int64
		duration int64
		age      time.Duration
	}{
		{"soft", 750, 1100, time.Minute},
		{"hard", 3500, 1100, time.Minute},
		{"burst", 40, 120, time.Minute},
		{"thinking", 0, 1100, time.Minute},
		{"disabled-soft", 750, 1100, time.Minute},
		{"earlier", 750, 1100, 2 * time.Hour},
		{"older", 750, 1100, 2 * 24 * time.Hour},
		{"boundary", 750, 1100, 24 * time.Hour},
		{"healthy", 250, 1100, time.Minute},
		{"probe", 3500, 1100, time.Minute},
		{"failed", 3500, 1100, time.Minute},
		{"nonstream", 3500, 1100, time.Minute},
		{"console", 3500, 1100, time.Minute},
		{"short", 31, 101, time.Minute},
		{"zero-window", 3500, 100, time.Minute},
		{"future", 3500, 1100, -time.Minute},
		{"reasoning-fallback", 40, 10000, time.Minute},
	} {
		row := accountModel{IdentityKey: testIdentityKey(seed.name), Provider: "grok_build", Name: seed.name, SourceKey: seed.name, Enabled: seed.name != "disabled-soft", AuthStatus: "active"}
		if seed.name == "console" {
			row.Provider = "grok_console"
		}
		if err := database.db.Create(&row).Error; err != nil {
			test.Fatal(err)
		}
		ids[seed.name] = row.ID
		record := audit.Record{
			RequestID: "user-" + seed.name, ClientKeyID: 1, ModelRouteID: 1, Provider: row.Provider, AccountID: &row.ID,
			StatusCode: 200, Streaming: true, OutputTokens: seed.output, FirstTokenMS: &firstToken, DurationMS: seed.duration, CreatedAt: now.Add(-seed.age),
		}
		switch seed.name {
		case "probe":
			record.RequestID = "quality_test_probe"
		case "thinking":
			record.ErrorCode = audit.ErrorQualityDegraded
		case "failed":
			record.StatusCode = 502
		case "nonstream":
			record.Streaming = false
		case "reasoning-fallback":
			lateFirst := int64(9980)
			record.FirstTokenMS = &lateFirst
			record.ReasoningTokens = 10
		}
		if err := audits.Create(ctx, record); err != nil {
			test.Fatal(err)
		}
	}
	for _, scenario := range []struct {
		name       string
		duration   time.Duration
		soft       float64
		hard       float64
		failClosed bool
		want       []string
	}{
		{"默认24小时", 24 * time.Hour, 500, 1000, false, []string{"soft", "hard", "burst", "thinking", "disabled-soft", "earlier", "boundary"}},
		{"1小时严格模式", time.Hour, 500, 1000, true, []string{"soft", "hard", "burst", "thinking", "disabled-soft"}},
		{"6小时", 6 * time.Hour, 500, 1000, false, []string{"soft", "hard", "burst", "thinking", "disabled-soft", "earlier"}},
		{"7天", 7 * 24 * time.Hour, 500, 1000, true, []string{"soft", "hard", "burst", "thinking", "disabled-soft", "earlier", "boundary", "older"}},
		{"自定义阈值", time.Hour, 800, 3000, false, []string{"hard", "burst", "thinking"}},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			input := repository.DegradeSummaryQuery{Start: now.Add(-scenario.duration), End: now, SoftTPS: scenario.soft, HardTPS: scenario.hard, MinGenerationMS: 1000, MinOutputTokens: 32, FailClosed: scenario.failClosed}
			guard, err := audits.SummarizeDegrade(ctx, input)
			if err != nil {
				test.Fatal(err)
			}
			want := slices.Clone(scenario.want)
			slices.Sort(want)
			if guard.AccountTotal != int64(len(want)) {
				test.Fatalf("守护命中数 = %d，期望 %d", guard.AccountTotal, len(want))
			}
			for _, filter := range []string{"history", "marked"} {
				var names []string
				for offset := 0; offset < len(want); offset += 2 {
					values, total, err := accounts.List(ctx, repository.AccountListQuery{
						Page:   repository.PageQuery{Limit: 2, Offset: offset, Sort: repository.SortQuery{Field: "name", Direction: repository.SortAscending}},
						Filter: repository.AccountListFilter{Provider: "grok_build", Quality: filter, QualityQuery: &input, Now: now},
					})
					if err != nil {
						test.Fatal(err)
					}
					if total != guard.AccountTotal {
						test.Fatalf("分页总数 %d 与守护 %d 不同", total, guard.AccountTotal)
					}
					pageIDs := make([]uint64, 0, len(values))
					for _, value := range values {
						names = append(names, value.Name)
						pageIDs = append(pageIDs, value.ID)
						if value.LastError != "" {
							test.Fatal("不应为了展示而写入处罚标记")
						}
					}
					history, err := audits.GetAccountDegradeHistory(ctx, pageIDs, input)
					if err != nil || len(history) != len(values) {
						test.Fatalf("页内历史未正确加载：%#v，%v", history, err)
					}
					for _, entry := range guard.Accounts {
						if got, ok := history[entry.ID]; ok {
							if got.Hits != entry.Hits || got.Soft != entry.Soft || got.Hard != entry.Hard || got.Burst != entry.Burst || got.Thinking != entry.Thinking || !got.Last.Equal(entry.Last) {
								test.Fatalf("历史详情与质量守护不一致：%#v，%#v", got, entry)
							}
						}
					}
				}
				if !slices.Equal(names, want) {
					test.Fatalf("%s = %v，期望 %v", filter, names, want)
				}
			}
			values, _, err := accounts.List(ctx, repository.AccountListQuery{Page: repository.PageQuery{Limit: 100}, Filter: repository.AccountListFilter{Quality: "none", QualityQuery: &input, Now: now}})
			if err != nil {
				test.Fatal(err)
			}
			for _, value := range values {
				if slices.Contains(want, value.Name) {
					test.Fatalf("降智账号 %s 不应进入无标记筛选", value.Name)
				}
			}
		})
	}
	input := repository.DegradeSummaryQuery{Start: now.Add(-24 * time.Hour), End: now, SoftTPS: 500, HardTPS: 1000, MinGenerationMS: 1000, MinOutputTokens: 32}
	values, total, err := accounts.List(ctx, repository.AccountListQuery{Page: repository.PageQuery{Limit: 20}, Filter: repository.AccountListFilter{Quality: "history", Status: "disabled", QualityQuery: &input, Now: now}})
	if err != nil || total != 1 || len(values) != 1 || values[0].ID != ids["disabled-soft"] {
		test.Fatalf("停用的soft账号仍须计入降智：%#v，%d，%v", values, total, err)
	}
	if err := accounts.UpdateHealth(ctx, ids["healthy"], account.ProviderBuild, 0, nil, account.LastErrorMissingThinking, false); err != nil {
		test.Fatal(err)
	}
	values, total, err = accounts.List(ctx, repository.AccountListQuery{Page: repository.PageQuery{Limit: 20, Search: "healthy"}, Filter: repository.AccountListFilter{Quality: "history", QualityQuery: &input, Now: now}})
	if err != nil || total != 1 || len(values) != 1 {
		test.Fatalf("无窗口内命中也应保留持久标记：%#v，%d，%v", values, total, err)
	}
}
