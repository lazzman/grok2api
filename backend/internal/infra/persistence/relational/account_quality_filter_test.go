package relational

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestAccountQualityFilter(test *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(test.TempDir(), "quality-filter.db"))
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		test.Fatal(err)
	}
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	future, past := now.Add(time.Hour), now.Add(-time.Hour)
	for _, seed := range []struct {
		name     string
		provider account.Provider
		enabled  bool
		marker   string
		cooldown *time.Time
	}{
		{"clean", account.ProviderBuild, true, "", nil},
		{"network", account.ProviderBuild, true, "upstream status 504", &future},
		{"manual-disabled", account.ProviderBuild, false, "", nil},
		{"legacy-null", account.ProviderBuild, true, "", nil},
		{"cooling", account.ProviderBuild, true, account.LastErrorMissingThinking, &future},
		{"recovered", account.ProviderBuild, true, account.LastErrorMissingThinking, &past},
		{"reenabled", account.ProviderBuild, true, account.LastErrorMissingThinkingDisabled, nil},
		{"history-disabled", account.ProviderBuild, false, account.LastErrorMissingThinking, nil},
		{"quality-disabled", account.ProviderBuild, false, account.LastErrorMissingThinkingDisabled, nil},
		{"console-history", account.ProviderConsole, true, account.LastErrorMissingThinking, nil},
		{"console-disabled", account.ProviderConsole, false, account.LastErrorMissingThinkingDisabled, nil},
		{"web-clean", account.ProviderWeb, true, "", nil},
	} {
		row := accountModel{
			IdentityKey: testIdentityKey(seed.name), Provider: string(seed.provider), Name: seed.name, SourceKey: seed.name,
			Enabled: seed.enabled, AuthStatus: string(account.AuthStatusActive), LastError: seed.marker, CooldownUntil: seed.cooldown,
		}
		if err := database.db.WithContext(ctx).Create(&row).Error; err != nil {
			test.Fatal(err)
		}
		if seed.name == "legacy-null" {
			if err := database.db.WithContext(ctx).Model(&row).Update("last_error", nil).Error; err != nil {
				test.Fatal(err)
			}
		}
	}
	accounts := NewAccountRepository(database)
	for _, scenario := range []struct {
		name     string
		provider string
		quality  string
		status   string
		search   string
		offset   int
		limit    int
		want     []string
	}{
		{name: "不筛选仍返回全部账号", want: []string{"clean", "network", "manual-disabled", "legacy-null", "cooling", "recovered", "reenabled", "history-disabled", "quality-disabled", "console-history", "console-disabled", "web-clean"}},
		{name: "无标记包含空值和其他故障", provider: "grok_build", quality: "none", want: []string{"clean", "network", "manual-disabled", "legacy-null"}},
		{name: "曾降智与标签一致", provider: "grok_build", quality: "history", want: []string{"cooling", "recovered", "reenabled", "history-disabled"}},
		{name: "降智停用不包含人工重新启用账号", provider: "grok_build", quality: "disabled", want: []string{"quality-disabled"}},
		{name: "曾降智与正常状态组合", provider: "grok_build", quality: "history", status: "active", want: []string{"recovered", "reenabled"}},
		{name: "曾降智与冷却状态组合", provider: "grok_build", quality: "history", status: "cooldown", want: []string{"cooling"}},
		{name: "曾降智与手动停用组合", provider: "grok_build", quality: "history", status: "disabled", want: []string{"history-disabled"}},
		{name: "降智停用与正常状态互斥", provider: "grok_build", quality: "disabled", status: "active"},
		{name: "无标记与普通故障冷却组合", provider: "grok_build", quality: "none", status: "cooldown", want: []string{"network"}},
		{name: "搜索与降智筛选组合", provider: "grok_build", quality: "history", search: "reenabled", want: []string{"reenabled"}},
		{name: "搜索不绕过降智筛选", provider: "grok_build", quality: "disabled", search: "reenabled"},
		{name: "筛选后分页且总数不受分页影响", provider: "grok_build", quality: "history", offset: 1, limit: 2, want: []string{"cooling", "recovered", "reenabled", "history-disabled"}},
		{name: "超出末页仍保留正确总数", provider: "grok_build", quality: "disabled", offset: 1, limit: 2, want: []string{"quality-disabled"}},
		{name: "Console曾降智", provider: "grok_console", quality: "history", want: []string{"console-history"}},
		{name: "Console降智停用", provider: "grok_console", quality: "disabled", want: []string{"console-disabled"}},
		{name: "Web无标记", provider: "grok_web", quality: "none", want: []string{"web-clean"}},
		{name: "不指定账号池时跨池筛选", quality: "disabled", want: []string{"quality-disabled", "console-disabled"}},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			limit := scenario.limit
			if limit == 0 {
				limit = 20
			}
			values, total, err := accounts.List(ctx, repository.AccountListQuery{
				Page:   repository.PageQuery{Offset: scenario.offset, Limit: limit, Search: scenario.search, Sort: repository.SortQuery{Field: "name", Direction: repository.SortAscending}},
				Filter: repository.AccountListFilter{Provider: scenario.provider, Quality: scenario.quality, Status: scenario.status, Now: now},
			})
			if err != nil {
				test.Fatal(err)
			}
			if total != int64(len(scenario.want)) {
				test.Fatalf("总数 = %d，期望 %d", total, len(scenario.want))
			}
			want := slices.Clone(scenario.want)
			slices.Sort(want)
			want = want[min(scenario.offset, len(want)):min(scenario.offset+limit, len(want))]
			names := make([]string, 0, len(values))
			for _, value := range values {
				names = append(names, value.Name)
			}
			if !slices.Equal(names, want) {
				test.Fatalf("账号 = %v，期望 %v", names, want)
			}
		})
	}
}
